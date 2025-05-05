# A-level Computing Project: Secure Password Utility

KeyVault is a zero-knowledge password manager with a ML-powered password health checker, built with Python and Flask

## Features
- Zero-knowledge architecture with AES-256 encryption
- 8-word mnemonic seed for key derivation (Argon2)
- ML Password Health Checker: A Random Forest model trained on 300,000 passwords (weak, medium, strong) to classify password strength.
- Customisable strong password generator 
- SQLite database with encrypted vaults
- Apache and HTTPS

