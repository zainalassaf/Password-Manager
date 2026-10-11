from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw,Type
import secrets
# Use Argon2id with a random salt to derive the AES key
# instead of using the master password directly.
# The salt makes the derived key unique, while Argon2id
# makes password guessing more expensive.
def derive_key(master_password : str , salt : bytes) -> bytes:
    key = hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        # time_cost controls how many iterations Argon2id performs.
        # A higher value increases the time required for each password attempt.
        time_cost=3,
        # memory_cost determines how much memory Argon2id uses for each operation.
        # 64 * 1024 KiB = 64 MiB of memory per operation.
        memory_cost=64*1024,
        # parallelism determines how many lanes Argon2id uses for parallel processing.
        # A value of 2 allows two lanes to work in parallel.
        parallelism=2,
        # Derive a 32-byte (256-bit) key for AES-256.
        hash_len=32,
        type=Type.ID
    )
    return key
# Generate a random 16-byte salt.
# 16 bytes is a common size for salts.
def generate_salt() ->bytes:
    # Use the secrets module to generate cryptographically secure random bytes.
    # It is designed for security-sensitive purposes.
    return secrets.token_bytes(16)
def encrypt_password(plaintext : str, key : bytes) -> tuple[bytes,bytes]:
    # Generate a unique nonce for each encryption to prevent nonce reuse
    # with the same AES-GCM key and ensure secure encryption.
    nonce=secrets.token_bytes(12)
    # I use AES-GCM because it encrypts the data and detects
    # if the encrypted data has been modified.
    aesgcm=AESGCM(key)
    ciphertext=aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        # We are not using AAD right now.
        # AAD allows us to authenticate additional data
        # without encrypting it, so changes to that data can be detected.
        None # AAD
    )
    return ciphertext,nonce
def decrypt_password(ciphertext : bytes , nonce : bytes , key : bytes) ->str:
    aesgcm=AESGCM(key)
    plaintext=aesgcm.decrypt(
        # We need to use the same nonce that was used during encryption
        # because AES-GCM requires it to decrypt and verify the ciphertext.
        nonce,
        ciphertext,
        None
    )
    # The decrypted data is returned as bytes,
    # so we decode it from UTF-8 back into a string.
    return plaintext.decode("utf-8")