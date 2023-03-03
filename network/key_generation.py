from umbral import SecretKey, Signer


# Generate Umbral keys for Alice.
alices_secret_key = SecretKey.random()
alices_public_key = alices_secret_key.public_key()

alices_signing_key = SecretKey.random()
alices_signer = Signer(alices_signing_key)
alices_verifying_key = alices_signing_key.public_key()


# Generate Umbral keys for Bob.
bobs_secret_key = SecretKey.random()
bobs_public_key = bobs_secret_key.public_key()
