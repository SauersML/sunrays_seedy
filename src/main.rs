//! A Rust program that automatically launches an embedded Tor client via arti-client,
//! generates an encrypted Solana wallet, and provides CLI commands: generate, address,
//! balance, send, and monitor. All requests go over Tor. No external Tor install needed.

use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{AesGcmSiv, Key, Nonce};
use aead::KeyInit;
use rand::RngCore;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::system_transaction;
use std::fs::{read, write};
use std::io::Write as IoWrite;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use zeroize::Zeroize;
use aes_gcm::aes::Aes256;
use tor_rtcompat::PreferredRuntime;

// For embedded Tor (arti-client):
use arti_client::TorClient;
use arti_client::config::TorClientConfig;

// =============== Constants ===============

/// Default Solana mainnet RPC endpoint.
const SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// The file where we store our Argon2-encrypted private key.
const ENCRYPTED_WALLET_FILE: &str = "wallet.enc";

/// AES-GCM-SIV uses a 96-bit (12-byte) nonce.
const NONCE_SIZE: usize = 12;

/// 1 SOL = 1_000_000_000 lamports
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

// We define a concrete type alias for AES-256-GCM-SIV:
type Aes256GcmSiv = AesGcmSiv<Aes256>;

// =============== Data Structures ===============

/// Stored inside `wallet.enc`, containing:
///   - Argon2 salt
///   - AES-GCM-SIV nonce
///   - Ciphertext of the 64-byte Keypair (secret key)
#[derive(Serialize, Deserialize)]
struct EncryptedKey {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Possible CLI commands
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

// =============== Main Entry ===============

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the subcommand from CLI
    let cmd = parse_command_line();

    // Start an embedded Tor SOCKS proxy on 127.0.0.1:9050 using arti-client.
    // We'll do this BEFORE any Solana RPC calls, so they're guaranteed to go over Tor.
    let _tor_client = start_tor_proxy(9050).await?;
    println!("\n[INFO] Tor is running on 127.0.0.1:9050. All Solana RPC calls go through it.\n");

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

// =============== Tor Setup ===============

/// Start an embedded Tor SOCKS proxy with arti-client on 127.0.0.1:9050.
async fn start_tor_proxy(port: u16) -> Result<TorClient<PreferredRuntime>> {
    // 1. Create a TorClientConfig with defaults
    let tor_cfg = TorClientConfig::default();

    // 2. Bootstrap a TorClient with that config
    let tor_client = TorClient::create_bootstrapped(tor_cfg)
        .await
        .map_err(|e| anyhow!("Failed to bootstrap embedded Tor: {e}"))?;

    // 3. Launch a SOCKS proxy listening on 127.0.0.1:9050 in the background
    //    so that future requests can route over Tor
    let local_addr = ("127.0.0.1", port);
    let socks_cfg = SocksProxyConfig::default();
    tokio::spawn(async move {
        if let Err(e) = run_socks_proxy(tor_client.clone(), local_addr, socks_cfg).await {
            eprintln!("[ERROR] Tor SOCKS proxy failed: {e}");
        }
    });

    Ok(tor_client)
}

// =============== CLI Parsing ===============

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

All Solana RPC requests go over an embedded Tor SOCKS proxy on 127.0.0.1:9050.
No external Tor install is needed.
"#
    );
}

// =============== Commands ===============

/// (1) Generate a new Keypair, (2) Prompt passphrase, (3) Encrypt to `wallet.enc`
async fn generate_wallet() -> Result<()> {
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
    let pubkey = keypair.pubkey();
    println!("\nYour Solana address (public key): {pubkey}\n");
    Ok(())
}

/// Decrypt wallet and show balance
async fn show_balance() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let pubkey = keypair.pubkey();

    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;
    let lamports = rpc_client.get_balance(&pubkey).await?;
    let sol = lamports_to_sol(lamports);

    println!("\nBalance of {pubkey}: {sol} SOL\n");
    Ok(())
}

/// Decrypt wallet, send <amount_sol> to <to> address
async fn send_sol_cmd(to: &str, amount_sol: f64) -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;

    let lamports = sol_to_lamports(amount_sol);
    let to_pubkey = to
        .parse()
        .map_err(|_| anyhow!("Invalid recipient pubkey: {to}"))?;

    let recent_blockhash = rpc_client.get_latest_blockhash().await?;
    let tx = system_transaction::transfer(&keypair, &to_pubkey, lamports, recent_blockhash);

    let sig = rpc_client.send_and_confirm_transaction(&tx).await?;
    println!(
        "\n[OK] Sent {amount_sol} SOL to {to}\nTransaction Signature: {sig}\n"
    );
    Ok(())
}

/// Decrypt wallet, monitor balance in a loop
async fn monitor_balance() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;
    let pubkey = keypair.pubkey();

    println!(
        "\nMonitoring balance of {pubkey} ... Press Ctrl+C to stop.\n"
    );
    loop {
        let lamports = rpc_client.get_balance(&pubkey).await?;
        let sol = lamports_to_sol(lamports);
        println!("Balance: {sol} SOL");
        sleep(Duration::from_secs(30)).await;
    }
}

// =============== Wallet Encryption/Decryption ===============

/// Prompt for passphrase twice
fn prompt_passphrase_twice() -> Result<String> {
    loop {
        print!("Enter a passphrase to encrypt your wallet: ");
        std::io::stdout().flush()?;
        let pass1 = read_password().context("Failed to read passphrase")?;

        print!("Confirm passphrase: ");
        std::io::stdout().flush()?;
        let pass2 = read_password().context("Failed to read passphrase")?;

        if pass1.is_empty() {
            println!("Passphrase cannot be empty. Try again.\n");
            continue;
        }
        if pass1 == pass2 {
            return Ok(pass1);
        } else {
            println!("Passphrases do not match. Try again.\n");
        }
    }
}

/// Encrypt the private key using Argon2 + AES-256-GCM-SIV
fn encrypt_keypair(keypair: &Keypair, passphrase: &str) -> Result<()> {
    let secret_key_bytes = keypair.to_bytes(); // 64 bytes

    // 1) Salt for Argon2
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // 2) Derive a 32-byte key
    let derived_key = derive_key_from_passphrase(passphrase, &salt)?;

    // 3) Generate random 12-byte nonce
    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // 4) Encrypt with AES256-GCM-SIV
    let cipher = Aes256GcmSiv::new(Key::from_slice(&derived_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), secret_key_bytes.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    let enc = EncryptedKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    };

    let serialized = bincode::serialize(&enc)
        .map_err(|e| anyhow!("Serialization error: {e}"))?;

    write(ENCRYPTED_WALLET_FILE, &serialized)?;
    Ok(())
}

/// Decrypt from `wallet.enc` using passphrase from user prompt
fn load_decrypt_keypair() -> Result<Keypair> {
    if !Path::new(ENCRYPTED_WALLET_FILE).exists() {
        return Err(WalletError::WalletNotFound.into());
    }

    println!("Enter wallet passphrase:");
    std::io::stdout().flush()?;
    let passphrase = read_password().context("Failed to read passphrase")?;
    if passphrase.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty."));
    }

    decrypt_keypair(&passphrase)
}

/// Actually decrypt the file
fn decrypt_keypair(passphrase: &str) -> Result<Keypair> {
    let file_data = read(ENCRYPTED_WALLET_FILE)?;
    let enc: EncryptedKey = bincode::deserialize(&file_data)
        .map_err(|_| WalletError::CorruptData)?;

    let derived_key = derive_key_from_passphrase(passphrase, &enc.salt)?;
    if enc.nonce.len() != NONCE_SIZE {
        return Err(WalletError::CorruptData.into());
    }

    let cipher = Aes256GcmSiv::new(Key::from_slice(&derived_key));
    let mut decrypted = cipher
        .decrypt(Nonce::from_slice(&enc.nonce), enc.ciphertext.as_ref())
        .map_err(|_| WalletError::InvalidPassphrase)?;

    if decrypted.len() != 64 {
        decrypted.zeroize();
        return Err(WalletError::CorruptData.into());
    }

    let keypair = Keypair::from_bytes(&decrypted)
        .map_err(|_| WalletError::CorruptData)?;

    // zeroize sensitive data
    decrypted.zeroize();
    Ok(keypair)
}

/// Derive a 32-byte key from passphrase + salt
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 derivation failed: {e}"))?;

    Ok(key)
}

// =============== File Security ===============

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

// =============== Solana RPC over Tor ===============

/// Create a Solana RPC client that uses the local Tor SOCKS proxy
async fn create_tor_rpc_client(url: &str) -> Result<RpcClient> {
    // We must build a custom `reqwest` client with SOCKS5 proxy = 127.0.0.1:9050
    let socks_proxy = reqwest::Proxy::all("socks5://127.0.0.1:9050")
        .map_err(|e| anyhow!("Failed to create SOCKS proxy: {e}"))?;

    let reqwest_client = reqwest::Client::builder()
        .proxy(socks_proxy)
        .build()
        .map_err(|e| anyhow!("Failed to build reqwest client: {e}"))?;

    use solana_client::http_sender::HttpSender;
    use std::sync::Arc;

    let sender = HttpSender::new_with_client(url, reqwest_client);
    let cfg = solana_client::rpc_client::RpcClientConfig {
        commitment_config: CommitmentConfig::confirmed(),
        // Default 30s timeouts, can be tweaked in RpcClientConfig
        ..solana_client::rpc_client::RpcClientConfig::default()
    };

    let rpc = RpcClient::new_sender(Arc::new(sender), cfg);
    Ok(rpc)
}

// =============== Helper Conversions ===============

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL
}

fn sol_to_lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_SOL).round() as u64
}
