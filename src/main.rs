//! A Rust program that automatically launches an embedded Tor client via arti-client,
//! generates an encrypted Solana wallet, and provides CLI commands: generate, address,
//! balance, send, and monitor. All requests go over an internal SOCKS5 proxy
//! at `127.0.0.1:9050`, started by `arti-client`—no external Tor needed!

#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use argon2::{Argon2, Algorithm, Params, Version};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;  // For RpcSender impl
use rand::RngCore;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use solana_client::{
    client_error::ClientError as SolanaClientError, client_error::Result as SolanaClientResult,
    nonblocking::rpc_client::RpcClient,
    rpc_client::RpcClientConfig,
    rpc_request::RpcRequest,
    rpc_sender::RpcSender,
};
use solana_client::rpc_sender::RpcTransportStats;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    signature::{Keypair, Signer},
    system_transaction,
};
use std::{
    fs::{self, read, write},
    process::Stdio,
    io::{BufRead, Write as IoWrite},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::time::sleep;
use tokio::process::Command as TokioCommand;
use tokio::{io::{AsyncBufReadExt, BufReader}, process::Child};
use zeroize::{Zeroize, Zeroizing};

const TOR_CHECK_URL: &str = "https://check.torproject.org/api/ip";
const DNS_LEAK_CHECK_URL: &str = "https://dnsleaktest.org/api/ip";
const IP_CHECK_URL: &str = "https://api.ipify.org";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0";

/// Default Solana mainnet RPC endpoint.
const SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// The file where we store our Argon2-encrypted private key.
const ENCRYPTED_WALLET_FILE: &str = "wallet.enc";

/// AES-256-GCM uses a 96-bit (12-byte) nonce.
const NONCE_SIZE: usize = 12;

/// 1 SOL = 1_000_000_000 lamports
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

/// A type alias for AES-256-GCM:
type Aes256GcmAlias = Aes256Gcm;

/// An object stored inside `wallet.enc`:
#[derive(Serialize, Deserialize)]
struct EncryptedKey {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ArtiTomlConfig {
    proxy: ArtiProxyConfig,
    storage: ArtiStorageConfig,
}

#[derive(Debug, Deserialize)]
struct ArtiProxyConfig {
    socks_listen: String,
}

#[derive(Debug, Deserialize)]
struct ArtiStorageConfig {
    cache_dir: String,
    state_dir: String,
}

/// CLI commands
enum Command {
    Generate,
    Address,
    Balance,
    Send { to: String, amount: f64 },
    Monitor,
    Help,
}

/// Custom wallet-related errors
#[derive(Debug, Error)]
enum WalletError {
    #[error("No wallet file found. Run `generate` first.")]
    WalletNotFound,
    #[error("Wallet data is corrupted.")]
    CorruptData,
    #[error("Invalid passphrase.")]
    InvalidPassphrase,
    #[error("Tor verification failed: {0}")]
    TorVerificationFailed(String),
    #[error("DNS leak detected: {0}")]
    DnsLeakDetected(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the subcommand from CLI.
    let cmd = parse_command_line();

    // Spawn the `arti` CLI proxy on 127.0.0.1:9050
    let _arti_child = start_tor_proxy(9050).await?; // We store the child handle in _arti_child to keep it alive while we run. (If _arti_child goes out of scope, the child might get dropped.)
    println!("\n[INFO] Arti (Tor) is running on 127.0.0.1:9050. All Solana RPC calls will be proxied.\n");
    
    // Verification sequence
    println!("\n[VERIFYING TOR CONNECTION]");
    verify_tor_connectivity().await?;
    if let Err(e) = check_dns_leak().await {
        eprintln!("{}", e);
    }
    compare_with_clear_net().await?;
    println!();

    // Dispatch to the requested command
    match cmd {
        Command::Generate => generate_wallet().await,
        Command::Address => show_address().await,
        Command::Balance => show_balance().await,
        Command::Send { to, amount } => send_sol_cmd(&to, amount).await,
        Command::Monitor => monitor_balance().await,
        Command::Help => {
            print_help();
            Ok(())
        }
    }
}

/// Start an embedded Tor SOCKS proxy using the `arti` CLI as a child process.
async fn start_tor_proxy(port: u16) -> Result<Child> {
    let mut child = TokioCommand::new("arti")
        .arg("proxy")
        .arg("-p")
        .arg(format!("{}", port))
        .arg("-o")
        .arg("logging.console=info")
        .stdout(Stdio::piped())  // async-compatible pipes
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn `arti proxy`: {e}"))?;

    // We'll watch arti's stdout for a line mentioning "Sufficiently bootstrapped" or "Bootstrapped 100%".
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("No STDOUT from `arti` process!"))?;

    let mut reader = BufReader::new(stdout).lines();

    println!("[INFO] Launching `arti proxy` on 127.0.0.1:{port}...");
    while let Some(line) = reader.next_line().await? {
        println!("arti> {}", line);

        // Arti might say "Sufficiently bootstrapped" or "Bootstrapped 100%" once it’s ready.
        // Right now, it says "INFO arti::subcommands::proxy: Sufficiently bootstrapped; system SOCKS now functional."
        if line.contains("Sufficiently bootstrapped") || line.contains("Bootstrapped 100%") {
            println!("[INFO] Arti is fully bootstrapped on 127.0.0.1:{port}.");
            break;
        }
    }

    // If we reach here, arti is presumably listening on `127.0.0.1:9050`.
    // We do NOT kill the child. Return it so you can kill it later if you want.
    Ok(child)
}


/// A custom `RpcSender` that routes all requests over an async `reqwest::Client` with socks5 proxy.
struct TorSender {
    url: String,
    client: Arc<reqwest::Client>,
    request_id: AtomicU64,
}

impl TorSender {
    /// Create a new TorSender with a reqwest::Client that uses socks5h proxy
    fn new(url: String) -> Result<Self> {
        // Configure socks5h for remote DNS resolution
        let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:9050")
            .map_err(|e| anyhow!("Failed to create Tor proxy: {e}"))?;

        // Build an async reqwest client
        let reqwest_client = reqwest::Client::builder()
            .proxy(proxy)
            // possibly set timeouts
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to build Tor-based reqwest client: {e}"))?;

        Ok(Self {
            url,
            client: Arc::new(reqwest_client),
            request_id: AtomicU64::new(0),
        })
    }
}

#[async_trait]
impl RpcSender for TorSender {
    async fn send<'a>(
        &'a self,
        request: RpcRequest,
        params: serde_json::Value
    ) -> SolanaClientResult<serde_json::Value> {
        // Each request increments an ID
        let request_id = self.request_id.fetch_add(1, Ordering::Relaxed);
        // Build JSON body
        let request_json = request.build_request_json(request_id, params);

        // Perform a POST to self.url
        let response = self.client
            .post(&self.url)
            .json(&request_json)
            .send()
            .await;

        let resp = match response {
            Ok(r) => r,
            Err(e) => {
                return Err(SolanaClientError::from(e));
            }
        };

        // Return error if non-200
        if !resp.status().is_success() {
            return Err(SolanaClientError::from(
                resp.error_for_status()
                    .expect_err("status already checked as not success")
            ));
        }

        let text_body = resp.text().await.map_err(SolanaClientError::from)?;
        let json: serde_json::Value = serde_json::from_str(&text_body)
            .map_err(SolanaClientError::from)?;

        if json.get("error").is_some() {
            // We expect the error to follow a certain shape
            // If there's an "error", it's typically: {"code":..., "message":...}
            let code = json["error"]["code"].as_i64().unwrap_or(-1);
            let message = json["error"]["message"].as_str().unwrap_or("unknown").to_string();

            return Err(SolanaClientError::new_with_request(
                solana_client::client_error::ClientErrorKind::RpcError(
                    solana_client::rpc_request::RpcError::RpcResponseError {
                        code,
                        message,
                        data: solana_client::rpc_request::RpcResponseErrorData::Empty,
                    }
                ),
                request
            ));
        }

        // Otherwise, parse the "result"
        Ok(json["result"].clone())
    }
    
    fn get_transport_stats(&self) -> RpcTransportStats {
        RpcTransportStats {
            request_count: self.request_id.load(Ordering::Relaxed) as usize,
            elapsed_time: Duration::from_secs(0),
            rate_limited_time: Duration::from_secs(0),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }
}

/// Parse command line arguments into a Command
fn parse_command_line() -> Command {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "generate" => Command::Generate,
        "address" => Command::Address,
        "balance" => Command::Balance,
        "send" => {
            if args.len() < 4 {
                eprintln!("Usage: {} send <RECIPIENT_PUBKEY> <AMOUNT_SOL>", args[0]);
                std::process::exit(1);
            }
            let to = args[2].clone();
            let amount_str = args[3].clone();
            let amount = match amount_str.parse::<f64>() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("Invalid amount: {amount_str}");
                    std::process::exit(1);
                }
            };
            Command::Send { to, amount }
        }
        "monitor" => Command::Monitor,
        "help" => Command::Help,
        _ => {
            print_help();
            std::process::exit(1);
        }
    }
}

/// Print usage help
fn print_help() {
    let exe = std::env::args()
        .next()
        .unwrap_or_else(|| "sunrays_seedy".to_string());
    println!(
r#"Usage:
  {exe} generate                Generate a new wallet (encrypted) in wallet.enc
  {exe} address                 Show the public address of your wallet
  {exe} balance                 Show the current balance of your wallet
  {exe} send <RECIPIENT> <AMT>  Send <AMT> SOL to <RECIPIENT>
  {exe} monitor                 Continuously monitor wallet balance (Ctrl+C to stop)
  {exe} help                    Show this help message

Examples:
  {exe} generate
  {exe} address
  {exe} balance
  {exe} send Fg6PaFpo... 0.001
  {exe} monitor

All Solana RPC requests are routed through an embedded Tor SOCKS proxy on 127.0.0.1:9050.
No external Tor installation is required."#
    );
}

/// Generate a new Keypair, prompt passphrase, encrypt to `wallet.enc`
async fn generate_wallet() -> Result<()> {
    if Path::new(ENCRYPTED_WALLET_FILE).exists() {
        println!(
            "[WARN] A wallet file '{}' already exists. Overwrite it? [y/N]",
            ENCRYPTED_WALLET_FILE
        );
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().lock().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborting wallet generation.");
            return Ok(());
        }
    }

    println!("Generating a new wallet...");

    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    println!("\n[INFO] Your new Solana address: {pubkey}");

    let passphrase = prompt_passphrase_twice()?;
    encrypt_keypair(&keypair, &passphrase)?;
    secure_file_permissions(ENCRYPTED_WALLET_FILE)?;

    println!(
        "\n[OK] Wallet saved to '{file}'. Keep your passphrase SECRET.\n",
        file = ENCRYPTED_WALLET_FILE
    );
    println!("You can run `address` or `balance` once you receive funds.\n");
    Ok(())
}

/// Decrypt wallet and show address
async fn show_address() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    println!("\nYour Solana address: {}\n", keypair.pubkey());
    Ok(())
}

/// Decrypt wallet and show balance
async fn show_balance() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;

    let lamports = rpc_client.get_balance(&keypair.pubkey()).await?;
    let sol = lamports_to_sol(lamports);
    println!("\nBalance of {}: {} SOL\n", keypair.pubkey(), sol);
    Ok(())
}

/// Decrypt wallet, send <amount_sol> to <to> address
async fn send_sol_cmd(to: &str, amount_sol: f64) -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;

    if amount_sol <= 0.0 {
        return Err(anyhow!("Amount must be greater than zero."));
    }
    
    let lamports = sol_to_lamports(amount_sol);
    let to_pubkey = to.parse().map_err(|_| anyhow!("Invalid recipient pubkey: {to}"))?;

    let recent_blockhash = rpc_client.get_latest_blockhash().await?;
    let tx = system_transaction::transfer(&keypair, &to_pubkey, lamports, recent_blockhash);

    let sig = rpc_client.send_and_confirm_transaction(&tx).await?;
    println!(
        "\n[OK] Sent {amount_sol} SOL to {to}\nTransaction Signature: {sig}\n"
    );
    Ok(())
}

/// Decrypt wallet, monitor balance
async fn monitor_balance() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;
    let pubkey = keypair.pubkey();

    println!("\nMonitoring balance of {pubkey} (Ctrl+C to stop)\n");
    loop {
        let lamports = rpc_client.get_balance(&pubkey).await?;
        let sol = lamports_to_sol(lamports);
        println!("Balance: {sol} SOL");
        sleep(Duration::from_secs(30)).await;
    }
}

/// Prompt for passphrase twice, returning a Zeroizing<String>
fn prompt_passphrase_twice() -> Result<Zeroizing<String>> {
    loop {
        print!("Enter a passphrase to encrypt your wallet: ");
        std::io::stdout().flush()?;
        let pass1 = Zeroizing::new(read_password().context("Failed to read passphrase")?);

        print!("Confirm passphrase: ");
        std::io::stdout().flush()?;
        let pass2 = Zeroizing::new(read_password().context("Failed to read passphrase")?);

        if pass1.is_empty() {
            println!("Passphrase cannot be empty. Try again.\n");
            continue;
        }
        if *pass1 == *pass2 {
            return Ok(pass1);
        } else {
            println!("Passphrases do not match. Try again.\n");
        }
    }
}

/// Encrypt private key with Argon2 + AES-256-GCM-SIV
fn encrypt_keypair(keypair: &Keypair, passphrase: &Zeroizing<String>) -> Result<()> {
    let secret_key_bytes = keypair.to_bytes(); // 64 bytes

    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let derived_key = derive_key_from_passphrase(passphrase, &salt)?;

    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256GcmAlias::new_from_slice(&derived_key)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), secret_key_bytes.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    let enc = EncryptedKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    };
    let serialized = bincode::serialize(&enc)?;
    write(ENCRYPTED_WALLET_FILE, &serialized)?;
    Ok(())
}

/// Decrypt from `wallet.enc` using passphrase from user prompt
fn load_decrypt_keypair() -> Result<Keypair> {
    if !Path::new(ENCRYPTED_WALLET_FILE).exists() {
        return Err(WalletError::WalletNotFound.into());
    }

    print!("Enter wallet passphrase: ");
    std::io::stdout().flush()?;
    let passphrase = Zeroizing::new(read_password().context("Failed to read passphrase")?);
    if passphrase.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty."));
    }

    decrypt_keypair(&passphrase)
}

/// Actually decrypt the file
fn decrypt_keypair(passphrase: &Zeroizing<String>) -> Result<Keypair> {
    let file_data = read(ENCRYPTED_WALLET_FILE)?;
    let enc: EncryptedKey =
        bincode::deserialize(&file_data).map_err(|_| WalletError::CorruptData)?;

    let derived_key = derive_key_from_passphrase(passphrase, &enc.salt)?;
    if enc.nonce.len() != NONCE_SIZE {
        return Err(WalletError::CorruptData.into());
    }

    let cipher = Aes256GcmAlias::new_from_slice(&derived_key)?;
    let mut decrypted = cipher
        .decrypt(Nonce::from_slice(&enc.nonce), enc.ciphertext.as_ref())
        .map_err(|_| WalletError::InvalidPassphrase)?;

    if decrypted.len() != 64 {
        decrypted.zeroize();
        return Err(WalletError::CorruptData.into());
    }
    let keypair = Keypair::from_bytes(&decrypted).map_err(|_| WalletError::CorruptData)?;
    decrypted.zeroize();
    Ok(keypair)
}

/// Derive a 32-byte key from passphrase + salt
fn derive_key_from_passphrase(
    passphrase: &Zeroizing<String>,
    salt: &[u8]
) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    // Use Argon2id with ~64MB memory, 3 passes, 1 thread
    let params = Params::new(65536, 3, 1, None)
        .map_err(|e| anyhow!("Invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 failed: {e}"))?;
    Ok(key)
}

/// Restrict file permissions on Unix (chmod 600).
#[allow(unused_variables)]
fn secure_file_permissions(path: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Create a Solana RPC client using our custom `TorSender`.
async fn create_tor_rpc_client(url: &str) -> Result<RpcClient> {
    let sender = TorSender::new(url.to_string())?;
    // `RpcClientConfig` does NOT have `commitment`, it has `commitment_config`.
    let rpc_config = RpcClientConfig {
        commitment_config: CommitmentConfig::confirmed(),
        ..Default::default()
    };
    Ok(RpcClient::new_sender(sender, rpc_config))
}

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL
}

fn sol_to_lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_SOL).round() as u64
}

async fn verify_tor_connectivity() -> Result<()> {
    let tor_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
        .timeout(Duration::from_secs(15))
        .build()?;

    let response = tor_client
        .get(TOR_CHECK_URL)
        .send()
        .await
        .context("Failed to reach Tor check service")?
        .text()
        .await?;

    let json: serde_json::Value = serde_json::from_str(&response)
        .context("Invalid response from Tor check service")?;

    if json["IsTor"].as_bool() != Some(true) {
        let msg = format!("Not using Tor! IP: {}", json["IP"].as_str().unwrap_or("unknown"));
        return Err(WalletError::TorVerificationFailed(msg).into());
    }

    println!(
        "\n[SUCCESS] Verified Tor exit node: {}",
        json["IP"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

async fn check_dns_leak() -> Result<()> {
    let tor_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(15))
        .build()?;

    let response = match tor_client
        .get(DNS_LEAK_CHECK_URL)
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            println!("[WARNING] DNS leak check request failed: {}", e);
            return Ok(());
        }
    };

    match response.json::<serde_json::Value>().await {
        Ok(json) => {
            if let Some(ip_field) = json.get("ip") {
                match ip_field {
                    serde_json::Value::String(ips) if ips.contains(',') => {
                        println!("[WARNING] Potential DNS leak detected. Contacted IPs:");
                        ips.split(',').for_each(|ip| println!("  - {}", ip.trim()));
                        Err(WalletError::DnsLeakDetected(ips.clone()).into())
                    }
                    _ => {
                        println!("[SUCCESS] No DNS leaks detected");
                        Ok(())
                    }
                }
            } else {
                println!("[WARNING] DNS leak check returned unexpected format");
                Ok(())
            }
        }
        Err(e) => {
            println!("[WARNING] Failed to parse DNS leak response: {}", e);
            Ok(())
        }
    }
}

async fn compare_with_clear_net() -> Result<()> {
    let tor_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(10))
        .build()?;

    let clear_client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(10))
        .build()?;

    let tor_ip = tor_client.get(IP_CHECK_URL).send().await?.text().await?;
    let clear_ip = clear_client.get(IP_CHECK_URL).send().await?.text().await?;

    println!("  Tor Network IP: {}", tor_ip);
    println!("  Clearnet IP:    {}", clear_ip);

    if tor_ip == clear_ip {
        println!("[WARNING] Tor and clearnet IPs match - connection might not be private!");
    } else {
        println!("[SUCCESS] Tor IP differs from clearnet IP");
    }

    Ok(())
}
