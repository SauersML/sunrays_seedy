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
    io::{BufRead, Write as IoWrite},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::time::sleep;
use zeroize::{Zeroize, Zeroizing};

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
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the subcommand from CLI.
    let cmd = parse_command_line();

    // Start an embedded Tor SOCKS proxy on 127.0.0.1:9050 using arti-client,
    // before making any Solana RPC calls.
    start_tor_proxy(9050).await?;
    println!("\n[INFO] Tor is running on 127.0.0.1:9050. All Solana RPC calls will be proxied.\n");

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

/// Start an embedded Tor SOCKS proxy using arti-client
async fn start_tor_proxy(port: u16) -> Result<()> {
    use arti_client::{
        config::{TorClientConfigBuilder, CfgPath},
        TorClient,
    };

    let data_dir = Path::new("/tmp/my_tor_data");
    if !data_dir.exists() {
        fs::create_dir(data_dir).map_err(|e| anyhow!("Failed to create .tor_data folder: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| anyhow!("Failed to set perms on .tor_data: {e}"))?;
        }
    }
    for sub in &["cache", "state", "keys", "persistent-state"] {
        let sub_path = data_dir.join(sub);
        if !sub_path.exists() {
            fs::create_dir_all(&sub_path)
                .map_err(|e| anyhow!("Cannot create {sub} subfolder: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&sub_path, fs::Permissions::from_mode(0o700))
                    .map_err(|e| anyhow!("Failed to set perms on {sub}: {e}"))?;
            }
        }
    }

    let cache_path = data_dir.join("cache");
    let state_path = data_dir.join("state");

    let mut config_builder = TorClientConfigBuilder::default();
    config_builder
        .storage()
        .cache_dir(CfgPath::new_literal(cache_path))
        .state_dir(CfgPath::new_literal(state_path));

    // Listen on 127.0.0.1:9050
    config_builder
        .override_net_params()
        .insert("socks_port".to_string(), port as i32);

    let config = config_builder
        .build()
        .map_err(|e| anyhow!("Failed to build Tor config: {e}"))?;

    if let Err(e) = TorClient::create_bootstrapped(config).await {
        eprintln!("[TOR BOOTSTRAP FAILURE] {:#?}", e);
        return Err(anyhow!("Failed to start Tor client: {e}"));
    }
    // If we got here, Tor is running on 127.0.0.1:9050
    Ok(())
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
