# Sunrays Seedy

A Rust CLI tool that automatically launches an **embedded Tor** client and then routes **all Solana RPC calls through Tor**. It also creates and manages an **Argon2-encrypted** Solana wallet (`wallet.enc`) with a simple command-line interface.

**Disclaimer:** This is an experimental demo/reference project. Use at your own risk. Always exercise caution when storing private keys and sending cryptocurrency!

## Features

- **Embedded Tor**: No external Tor installation required; runs on `127.0.0.1:9050`.
- **At-Rest Encryption**: Wallet keys stored in `wallet.enc` are protected with Argon2id + AES-256-GCM.
- **Zeroize**: Passphrases and decrypted key material in memory are zeroized when possible.
- **Simple CLI**: 
  - `generate` creates a new wallet
  - `address` shows public address
  - `balance` queries your current SOL balance
  - `send <RECIPIENT> <AMOUNT>` sends SOL
  - `monitor` polls your balance every 30 seconds

## How It Works

1. On each run, the program boots an **embedded Tor** process in the background, storing Tor data in `/tmp/my_tor_data`.
2. Once Tor is bootstrapped, all subsequent Solana RPC connections go through a SOCKS5 proxy at `127.0.0.1:9050`.
3. If you run commands like `balance` or `send`, the tool will:
   - Prompt for your wallet passphrase
   - Decrypt your `wallet.enc` via Argon2id (64MB memory, 3 passes) + AES-256-GCM
   - Perform the requested Solana operation.

## Installation

```
cargo install sunrays_seedy
```

_Or:_

1. **Prerequisites**:  
   - [Rust](https://www.rust-lang.org/tools/install) (1.60+ recommended)
   - A Unix-like OS is recommended (Linux / macOS). Windows is possible but has not been extensively tested.
2. **Clone this repo**:
   ```bash
   git clone https://github.com/youruser/sunrays_seedy.git
   cd sunrays_seedy
   ```
3. **Build**:
   ```bash
   cargo build --release
   ```
4. **Run**:
   ```bash
   ./target/release/sunrays_seedy help
   ```
   or simply:
   ```bash
   cargo run -- help
   ```

## Usage

```bash
# Generate a new wallet (encrypted in `wallet.enc`)
./target/release/sunrays_seedy generate

# Show the address (public key)
./target/release/sunrays_seedy address

# Check balance
./target/release/sunrays_seedy balance

# Send funds
./target/release/sunrays_seedy send <RECIPIENT_PUBKEY> <AMOUNT_SOL>
# Example:
./target/release/sunrays_seedy send Fg6PaFpoGXkYsidMpWTKhtTwrSdgnkXpese2Zu2R7EVk 0.01

# Monitor balance (poll every 30s)
./target/release/sunrays_seedy/sunrays_seedy monitor
```

### Important Notes

- **Passphrase Strength**: The security of your `wallet.enc` file depends entirely on the passphrase you choose. Pick something lengthy and random if you’re storing real funds.
- **Tor Data Directory**: The tool creates `/tmp/my_tor_data` (mode 0700). It does **not** remove or clear it on exit. If you need ephemeral usage, you can modify the code to remove it afterwards.
- **Mainnet Only**: Currently, it’s hard-coded to `https://api.mainnet-beta.solana.com`. If you need devnet or testnet, you must adjust the code or add a CLI parameter.
- **Port Conflicts**: By default, it starts Tor on `127.0.0.1:9050`. If you already have Tor or something else bound to that port, the program will fail to start. Edit the code or free the port to fix this.

## Security Considerations

- **Local Attacker Model**: If an attacker has full local admin privileges, they might capture your passphrase via keylogging or memory inspection. This is beyond the scope of normal “software-only” wallets.
- **Argon2id Parameters**: Currently set to 64 MB memory, 3 passes. Adjust in `derive_key_from_passphrase()` if you want a lighter or heavier cost.
- **Nonce Reuse**: Each encryption uses a fresh random nonce. Make sure you **never** reuse the same encrypted file with the same nonce. This code automatically prevents that by generating new random nonces every time you do `generate`.

## Do not use this program
It probably will not work, and has not been tested.
