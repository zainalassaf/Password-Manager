# Smart Encrypted Password Vault

## What is the project?

Smart Encrypted Password Vault is a simple password manager that works through the console.

It stores the website name, Gmail, and password of an account. The passwords are stored in the database in encrypted form.

## Features

- Add account
- Get account
- Search account
- Update account
- Delete account
- Change master password

## Security

- **Salt:** 16 random bytes generated using the `secrets` library.
- **Argon2id:** Used to derive the AES key from the master password and salt.
- **AES Key:** A 32-byte key derived using Argon2id.
- **AES-GCM:** Used to encrypt and decrypt the passwords.
- **Master Password:** Used to unlock the password vault.
- **Nonce:** 12 random bytes generated for each encryption.
- **Authentication Tag:** Used by AES-GCM to detect if encrypted data was changed.
- **Transaction / Rollback:** Used when changing the master password so the database can return to its previous state if something goes wrong.

## Project Structure

```text id="5h2m9k"
main.py
database.py
crypto.py
info.db
```

- `main.py` — Main program and user menu.
- `database.py` — Database operations.
- `crypto.py` — Encryption, decryption, salt, nonce, and key derivation.
- `info.db` — SQLite database.

## Requirements

- Python 3.13+
- argon2-cffi
- cryptography

## Installation & Running

### Installation

Make sure Python 3.13+ is installed.

Install the required libraries:

pip install cryptography argon2-cffi

### Running

Run the program using:

python main.py

## How Authentication Works

When I enter the master password, Argon2id uses the password and the stored salt to derive the AES key.

The program then decrypts the stored `VAULT_OK` value using the AES key.

If the decrypted value is `VAULT_OK`, the master password is correct and the program opens the vault.

The AES key is then used to encrypt and decrypt the account passwords.

## Changing Master Password

When I change the master password, the program starts a transaction.

First, all passwords are decrypted using the old AES key.

If a password cannot be decrypted, the transaction is rolled back.

Then a new salt and AES key are generated from the new master password.

All passwords are encrypted again using the new AES key.

New verification data is also created for the new master password.

If everything succeeds, the transaction is committed and the new AES key is used.

## Security Limitations / Notes

- This project is made for educational purposes.
- There is no master password recovery.
- If the master password is forgotten, the encrypted passwords cannot be recovered.
- The `info.db` file contains encrypted account data and should not be uploaded to a public repository.