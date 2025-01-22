use anyhow::{anyhow, Result};
use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    AesGcmSiv, Key, Nonce,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rand::RngCore;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use solana_client::{
    rpc_client::RpcClient,
    rpc_request::RpcRequest,
    rpc_sender::HttpSender,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    signature::{Keypair, Signature, Signer},
    system_transaction,
};
use std::{
    fs::{read, write},
    io::Write,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use tokio::time::sleep;
use thiserror::Error;

/// Default RPC endpoint (Mainnet Beta).
/// You may change this to devnet or your own node as desired.
const SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Filename to store your encrypted wallet (private key).
const ENCRYPTED_WALLET_FILE: &str = "wallet.enc";

/// AES-GCM-SIV Nonce size in bytes (96 bits).
const NONCE_SIZE: usize = 12;

/// We will store this struct (serialized) inside the encrypted file.
#[derive(Serialize, Deserialize)]
struct EncryptedKey {
    /// Random salt used for Argon2 key derivation.
    salt: Vec<u8>,
    /// The nonce used for AES-GCM-SIV encryption.
    nonce: Vec<u8>,
    /// Actual ciphertext of the private key bytes.
    ciphertext: Vec<u8>,
}

/// Errors that might occur in our wallet operations.
#[derive(Debug, Error)]
enum WalletError {
    #[error("No wallet found. Have you run `generate`?")]
    WalletNotFound,
    #[error("Invalid encryption data in the wallet file.")]
    CorruptData,
    #[error("Invalid passphrase.")]
    InvalidPassphrase,
}

/// Command-line subcommands
#[derive(Debug)]
enum Command {
    Generate,
    Address,
    Balance,
    Send { to: String, amount: f64 },
    Monitor,
    Help,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line
    let cmd = parse_command_line();

    match cmd {
        Command::Generate => {
            generate_wallet().await?;
        }
        Command::Address => {
            let keypair = load_decrypt_keypair()?;
            println!("Your Solana address (public key) is:\n{}", keypair.pubkey());
        }
        Command::Balance => {
            let keypair = load_decrypt_keypair()?;
            let client = create_tor_rpc_client(SOLANA_RPC_URL)?;
            let balance_sol = get_balance_sol(&client, &keypair.pubkey())?;
            println!("Balance of {} is {} SOL", keypair.pubkey(), balance_sol);
        }
        Command::Send { to, amount } => {
            let keypair = load_decrypt_keypair()?;
            let client = create_tor_rpc_client(SOLANA_RPC_URL)?;
            let sig = send_sol(&client, &keypair, &to, amount)?;
            println!("Sent {} SOL to {} in transaction {}", amount, to, sig);
        }
        Command::Monitor => {
            // Repeatedly fetch balance and display it
            // This is a simple example that checks balance every 30 seconds.
            let keypair = load_decrypt_keypair()?;
            let client = create_tor_rpc_client(SOLANA_RPC_URL)?;
            let pubkey = keypair.pubkey();

            println!("Monitoring balance for {}\n(Ctrl+C to stop)...", pubkey);
            loop {
                let balance_sol = get_balance_sol(&client, &pubkey)?;
                println!("Balance: {} SOL", balance_sol);
                sleep(Duration::from_secs(30)).await;
            }
        }
        Command::Help => {
            print_help();
        }
    }

    Ok(())
}

/// Parse minimal command line arguments into our Command enum.
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
            let amount = match f64::from_str(&amount_str) {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("Invalid amount: {}", amount_str);
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

/// Print usage instructions
fn print_help() {
    let exe = std::env::args().next().unwrap_or("solana_wallet_tor".into());
    println!(
        r#"Usage:
  {exe} generate                Generate a new wallet and store encrypted private key
  {exe} address                 Show the public address of your wallet
  {exe} balance                 Show the current balance of your wallet
  {exe} send <RECIPIENT> <AMT>  Send <AMT> SOL to <RECIPIENT>
  {exe} monitor                 Continuously monitor wallet balance
  {exe} help                    Show this help message

Examples:
  {exe} generate
  {exe} address
  {exe} balance
  {exe} send Fg6PaFpo... 0.001
  {exe} monitor

By default, this connects to {url} via Tor at 127.0.0.1:9050.
"#,
        exe = exe,
        url = SOLANA_RPC_URL,
    );
}

/// Creates a new wallet (Keypair), encrypts it with passphrase, and writes to `wallet.enc`.
async fn generate_wallet() -> Result<()> {
    // Generate new keypair
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();

    println!("Generating new wallet...");
    println!("Your new public address is: {}", pubkey);
    println!("\nIMPORTANT: Store your passphrase in a safe place. If you lose it, you lose access.");

    // Prompt for passphrase
    let passphrase = loop {
        print!("Enter a passphrase to encrypt your new wallet file: ");
        std::io::stdout().flush()?;
        let p1 = read_password().unwrap_or_default();

        print!("Confirm passphrase: ");
        std::io::stdout().flush()?;
        let p2 = read_password().unwrap_or_default();

        if p1.is_empty() {
            println!("Passphrase cannot be empty. Try again.\n");
            continue;
        }

        if p1 == p2 {
            break p1;
        } else {
            println!("Passphrases do not match. Try again.\n");
        }
    };

    // Encrypt and write to file
    encrypt_keypair(&keypair, &passphrase)?;

    println!("\nWallet successfully generated and encrypted to '{}'.", ENCRYPTED_WALLET_FILE);
    println!("You can run `address` to see your public address at any time.\n");
    Ok(())
}

/// Load & decrypt the stored wallet file using passphrase from user prompt.
fn load_decrypt_keypair() -> Result<Keypair> {
    if !std::path::Path::new(ENCRYPTED_WALLET_FILE).exists() {
        return Err(WalletError::WalletNotFound.into());
    }

    println!("Enter passphrase to decrypt your wallet: ");
    std::io::stdout().flush()?;
    let passphrase = read_password().unwrap_or_default();
    if passphrase.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty."));
    }

    let keypair = decrypt_keypair(&passphrase)?;
    Ok(keypair)
}

/// Encrypt the given Keypair to `wallet.enc` using the provided passphrase.
fn encrypt_keypair(keypair: &Keypair, passphrase: &str) -> Result<()> {
    let secret_key = keypair.to_bytes(); // 64 bytes

    // Generate random salt for Argon2
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive encryption key from passphrase
    let derived_key = derive_key_from_passphrase(passphrase, &salt)?;

    // Now encrypt with AES-GCM-SIV
    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = Key::from_slice(&derived_key);
    let cipher = AesGcmSiv::new(key);

    let ciphertext = cipher
        .encrypt(nonce, secret_key.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    let enc_struct = EncryptedKey {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    };

    let serialized = bincode::serialize(&enc_struct)?;
    write(ENCRYPTED_WALLET_FILE, serialized)?;

    Ok(())
}

/// Decrypt the Keypair from `wallet.enc` using provided passphrase.
fn decrypt_keypair(passphrase: &str) -> Result<Keypair> {
    let data = read(ENCRYPTED_WALLET_FILE)?;
    let enc: EncryptedKey = bincode::deserialize(&data)
        .map_err(|_| WalletError::CorruptData)?;

    let derived_key = derive_key_from_passphrase(passphrase, &enc.salt)?;

    // AES-GCM-SIV
    if enc.nonce.len() != NONCE_SIZE {
        return Err(WalletError::CorruptData.into());
    }
    let key = Key::from_slice(&derived_key);
    let cipher = AesGcmSiv::new(key);
    let nonce = Nonce::from_slice(&enc.nonce);

    let decrypted = cipher
        .decrypt(nonce, enc.ciphertext.as_ref())
        .map_err(|_| WalletError::InvalidPassphrase)?;

    if decrypted.len() != 64 {
        return Err(WalletError::CorruptData.into());
    }

    // Reconstruct Keypair from 64 bytes
    let keypair = Keypair::from_bytes(&decrypted)
        .map_err(|_| WalletError::CorruptData)?;

    Ok(keypair)
}

/// Derive a 32-byte key from passphrase + salt using Argon2.
/// This is a minimal example; maybe tune Argon2 parameters.
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>> {
    // We will produce a 32-byte key
    let mut key = vec![0u8; 32];

    // Argon2id recommended for password hashing
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("Argon2 key derivation failed"))?;

    Ok(key)
}

/// Create a Solana RpcClient that routes requests via Tor on 127.0.0.1:9050.
fn create_tor_rpc_client(url: &str) -> Result<RpcClient> {
    let proxy = reqwest::Proxy::all("socks5://127.0.0.1:9050")?;
    let reqwest_client = reqwest::Client::builder()
        .proxy(proxy)
        .build()?;

    let sender = HttpSender::new_with_client(reqwest_client);
    let rpc_client = RpcClient::new_sender(
        sender,
        url.to_string(),
        CommitmentConfig::confirmed(),
    );
    Ok(rpc_client)
}

/// Get the balance (in SOL) for the given public key.
fn get_balance_sol(client: &RpcClient, pubkey: &solana_sdk::pubkey::Pubkey) -> Result<f64> {
    let lamports = client.get_balance(pubkey)?;
    let sol = lamports_to_sol(lamports);
    Ok(sol)
}

/// Send the given amount of SOL from `from_keypair` to address `to_pubkey_str`.
fn send_sol(
    client: &RpcClient,
    from_keypair: &Keypair,
    to_pubkey_str: &str,
    amount_sol: f64,
) -> Result<Signature> {
    let to_pubkey = solana_sdk::pubkey::Pubkey::from_str(to_pubkey_str)
        .map_err(|_| anyhow!("Invalid recipient pubkey"))?;

    // Convert SOL to lamports
    let lamports = sol_to_lamports(amount_sol);

    // Build transaction
    let recent_blockhash = client.get_latest_blockhash()?;
    let tx = system_transaction::transfer(from_keypair, &to_pubkey, lamports, recent_blockhash);

    // Send transaction
    let signature = client.send_and_confirm_transaction(&tx)?;
    Ok(signature)
}

/// Convert lamports to SOL (1 SOL = 1_000_000_000 lamports)
fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

/// Convert SOL to lamports
fn sol_to_lamports(sol: f64) -> u64 {
    (sol * 1_000_000_000.0) as u64
}
