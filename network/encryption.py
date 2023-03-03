from umbral import encrypt, decrypt_original

from key_generation import alices_public_key, alices_secret_key


# Encrypt data with Alice's public key.
plaintext = b"Proxy Re-Encryption is cool!"
capsule, ciphertext = encrypt(alices_public_key, plaintext)

# Decrypt data with Alice's private key.
cleartext = decrypt_original(alices_secret_key, capsule, ciphertext)
