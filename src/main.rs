//! A Rust program that automatically launches an embedded Tor client via Arti,
//! generates an encrypted Solana wallet, and provides CLI commands to address,
//! balance, send, and monitor that wallet over Tor.
//!
//! No external Tor installation needed.


use anyhow::{anyhow, Context, Result};
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{AesGcmSiv, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::transaction::Transaction;
use solana_sdk::system_instruction;
use std::fs::{read, write, File};
use std::io::Write as IoWrite;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use zeroize::Zeroize;

// For embedded Tor (Arti):
use arti::config::TorClientConfig;
use arti::TorClient;

// =============== Constants ===============

/// Default Solana mainnet RPC endpoint.
const SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// The file where we store our Argon2-encrypted private key.
const ENCRYPTED_WALLET_FILE: &str = "wallet.enc";

/// AES-GCM-SIV uses a 96-bit (12-byte) nonce.
const NONCE_SIZE: usize = 12;

/// 1 SOL = 1_000_000_000 lamports
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

// =============== Data Structures ===============

/// Stored inside `wallet.enc`, containing:
///   - Argon2 salt
///   - AES-GCM-SIV nonce
///   - Ciphertext
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

    // IMPORTANT: Start the embedded Tor client so we can make RPC calls over Tor.
    // We do this *before* certain commands so that everything consistently uses Tor.
    let tor_client = start_tor_proxy(9050).await?;
    println!("\n[INFO] Tor is running. All Solana RPC requests will be routed over Tor.\n");

    // Depending on the command, perform the requested action.
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

// =============== Tor Setup (Arti) ===============

/// Start an embedded Tor Socks proxy on `127.0.0.1:<port>` using Arti.
/// This will bootstrap the Tor network in the background.
async fn start_tor_proxy(port: u16) -> Result<TorClient> {
    println!("[INFO] Bootstrapping Tor (Arti) client on port {port}...");
    let cfg = TorClientConfig::default();
    let tor_client = TorClient::bootstrap(cfg)
        .await
        .map_err(|e| anyhow!("Failed to bootstrap Tor: {e}"))?;

    // This spawns a SOCKS proxy in the background
    tor_client
        .run_socks_proxy(("127.0.0.1", port), false)
        .await
        .map_err(|e| anyhow!("Failed to start Tor SOCKS proxy: {e}"))?;

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
        .unwrap_or_else(|| "solana_wallet_tor".to_string());
    println!(
        r#"Usage:
  {exe} generate                Generate a new wallet and store encrypted private key
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

All Solana RPC requests are routed through an embedded Tor client.
No external Tor installation is needed.
"#
    );
}

// =============== Commands ===============

/// 1) Generate a new wallet + store in `wallet.enc`, 2) Prompt for passphrase, 3) Encrypt & write
async fn generate_wallet() -> Result<()> {
    println!("Generating a new wallet...");

    // Generate new keypair
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    println!("\n[INFO] Your new Solana address: {pubkey}");

    // Prompt passphrase & confirm
    let passphrase = prompt_passphrase_twice()?;

    // Encrypt
    encrypt_keypair(&keypair, &passphrase)?;

    // Attempt to restrict file permissions on Unix (0600).
    secure_file_permissions(ENCRYPTED_WALLET_FILE)?;

    println!(
        "\n[OK] Wallet saved to '{file}'. Keep your passphrase SECRET.\n\
You can run `address` or `balance` once you have funds.\n",
        file = ENCRYPTED_WALLET_FILE
    );
    Ok(())
}

/// Show the wallet's public address
async fn show_address() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let pubkey = keypair.pubkey();
    println!("\nYour Solana address (public key): {pubkey}\n");
    Ok(())
}

/// Check the wallet's balance (via Solana RPC over Tor)
async fn show_balance() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let pubkey = keypair.pubkey();

    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;
    let lamports = rpc_client.get_balance(&pubkey).await?;
    let sol = lamports_to_sol(lamports);
    println!("\nBalance of {pubkey}: {sol} SOL\n");
    Ok(())
}

/// Send the given amount of SOL to the given recipient address
async fn send_sol_cmd(to: &str, amount_sol: f64) -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;

    // Convert to lamports
    let lamports = sol_to_lamports(amount_sol);

    // Check recipient pubkey
    let to_pubkey = to
        .parse()
        .map_err(|_| anyhow!("Invalid recipient pubkey: {to}"))?;

    // Get recent blockhash
    let blockhash = rpc_client.get_latest_blockhash().await?;

    // Create transaction
    let tx = system_transaction::transfer(&keypair, &to_pubkey, lamports, blockhash);

    // Send+confirm
    let sig = rpc_client.send_and_confirm_transaction(&tx).await?;
    println!(
        "\n[OK] Sent {amount_sol} SOL to {to}\nTransaction Signature: {sig}\n"
    );
    Ok(())
}

/// Monitor the wallet's balance in a loop (every 30s)
async fn monitor_balance() -> Result<()> {
    let keypair = load_decrypt_keypair()?;
    let pubkey = keypair.pubkey();
    let rpc_client = create_tor_rpc_client(SOLANA_RPC_URL).await?;

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

/// Prompt for passphrase, confirm it, ensure it is not empty.
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

/// Encrypt the private key with Argon2 + AES-GCM-SIV, then write to file
fn encrypt_keypair(keypair: &Keypair, passphrase: &str) -> Result<()> {
    let secret_key_bytes = keypair.to_bytes(); // 64 bytes

    // Argon2 salt (16 bytes)
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive a 32-byte key from passphrase + salt
    let derived_key = derive_key_from_passphrase(passphrase, &salt)?;

    // Generate random 12-byte nonce
    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = AesGcmSiv::new(Key::from_slice(&derived_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            secret_key_bytes.as_ref(),
        )
        .map_err(|_| anyhow!("Encryption failed"))?;

    // Assemble EncryptedKey structure
    let enc = EncryptedKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    };

    // Serialize with bincode
    let serialized = bincode::serialize(&enc)
        .map_err(|e| anyhow!("Serialization error: {e}"))?;

    // Write to file
    write(ENCRYPTED_WALLET_FILE, &serialized)?;

    Ok(())
}

/// Load+decrypt the local `wallet.enc` using user-passphrase from prompt
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

/// Decrypt the Keypair from `wallet.enc` using provided passphrase
fn decrypt_keypair(passphrase: &str) -> Result<Keypair> {
    let file_data = read(ENCRYPTED_WALLET_FILE)?;
    let enc: EncryptedKey = bincode::deserialize(&file_data)
        .map_err(|_| WalletError::CorruptData)?;

    // Derive key
    let derived_key = derive_key_from_passphrase(passphrase, &enc.salt)?;

    // Decrypt
    if enc.nonce.len() != NONCE_SIZE {
        return Err(WalletError::CorruptData.into());
    }
    let cipher = AesGcmSiv::new(Key::from_slice(&derived_key));
    let mut decrypted = cipher
        .decrypt(Nonce::from_slice(&enc.nonce), enc.ciphertext.as_ref())
        .map_err(|_| WalletError::InvalidPassphrase)?;

    if decrypted.len() != 64 {
        decrypted.zeroize();
        return Err(WalletError::CorruptData.into());
    }

    // Construct Keypair
    let keypair = Keypair::from_bytes(&decrypted)
        .map_err(|_| WalletError::CorruptData)?;

    // Wipe sensitive data from memory
    decrypted.zeroize();
    Ok(keypair)
}

/// Derive a 32-byte key from passphrase + salt using Argon2id
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 derivation failed: {e}"))?;
    Ok(key)
}

// =============== File Security ===============

/// Attempt to restrict file permissions on Unix (chmod 600).
/// Non-Unix systems will ignore this.
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

/// Create a Solana RPC client that talks over our local Tor SOCKS proxy at 127.0.0.1:<port>
async fn create_tor_rpc_client(url: &str) -> Result<RpcClient> {
    // Build a custom reqwest client that uses the local Tor SOCKS5 proxy
    let socks_url = "socks5://127.0.0.1:9050";
    let proxy = reqwest::Proxy::all(socks_url)
        .map_err(|e| anyhow!("Failed to create SOCKS proxy: {e}"))?;
    let reqwest_client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .map_err(|e| anyhow!("Failed to build reqwest client: {e}"))?;

    // The nonblocking Solana client can be constructed with a custom HttpSender under the hood.
    let rpc = RpcClient::new_with_commitment_and_options(
        url.to_string(),
        CommitmentConfig::confirmed(),
        solana_client::nonblocking::rpc_client::RpcClientOptions {
            client: Some(reqwest_client),
        },
    );
    Ok(rpc)
}

// =============== Helper Conversions ===============

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL
}

fn sol_to_lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_SOL).round() as u64
}
