# Tor-Enabled Solana Wallet CLI

Note: this does not work, so attempt to use it at your own risk.

This is a Rust program that provides a minimalistic Solana wallet over an **embedded Tor client**, so you do **not** need a separate Tor installation. All Solana RPC traffic can be routed through Tor for greater privacy.

## Features

- **No External Tor**  
  Automatically starts a Tor SOCKS proxy via [arti-client](https://docs.rs/arti-client/latest/arti_client/).  
- **Secure Key Storage**  
  The wallet's private key is encrypted in `wallet.enc` using:
  - [Argon2] password-based key derivation
  - [AES-256-GCM-SIV] encryption
  - Secure random salts and nonces
  - Zeroization of in-memory secrets
- **Convenient Commands**  
  - `generate`: Create a new wallet
  - `address`: Show public address
  - `balance`: Fetch current balance
  - `send`: Send SOL to a recipient
  - `monitor`: Continuously watch for balance changes

## Usage

After building (see below), run the binary with one of these subcommands:

```
mywallet generate
mywallet address
mywallet balance
mywallet send <RECIPIENT_ADDRESS> <AMOUNT_SOL>
mywallet monitor
mywallet help
```

### 1. Generate a Wallet
```bash
mywallet generate
```
This prompts for a passphrase twice, encrypts a newly generated Solana keypair, and stores it in `wallet.enc`.

### 2. Show Address
```bash
mywallet address
```
Decrypts your wallet (prompts for passphrase) and prints the public Solana address.

### 3. Show Balance
```bash
mywallet balance
```
Fetches your SOL balance from the Solana mainnet.

### 4. Send SOL
```bash
mywallet send <RECIPIENT> <AMOUNT>
```
Example:
```bash
mywallet send 4yMAbzS... 0.5
```
Sends 0.5 SOL to `<RECIPIENT>`.

### 5. Monitor Balance
```bash
mywallet monitor
```
Continuously fetches your balance every 30 seconds until you press <kbd>Ctrl+C</kbd>.

### 6. Help
```bash
mywallet help
```
Prints usage instructions.

## Building

1. Install [Rust and Cargo](https://www.rust-lang.org/tools/install).  
2. Clone this repository.  
3. Run:
   ```bash
   cargo build --release
   ```
4. The compiled binary will be at `target/release/mywallet` (Linux/macOS) or `target\release\mywallet.exe` (Windows).

## Tor Proxy Note

By default, this application starts a Tor client listening on `127.0.0.1:9050`. However, **you must make sure ** that the Solana RPC traffic actually uses this SOCKS proxy. Otherwise, the traffic may go out over clearnet.

## Security Warnings

- **Passphrase**: A strong passphrase is essential. If lost, the wallet cannot be recovered.  
- **Existing Wallets**: Running `mywallet generate` overwrites the existing `wallet.enc` without warning.  
- **Local Files**: Keep `wallet.enc` in a secure folder. Anyone who obtains it (and your passphrase) can spend your funds.  
- **Tor Data Directory**: By default, the Tor client stores state/cache files in `/tmp/my_tor_data`.
- **No Guarantee**: This code is a proof-of-concept which almost certainly will not work.
