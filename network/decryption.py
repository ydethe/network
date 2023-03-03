from umbral import pre

from key_generation import bobs_secret_key, alices_public_key
from reencryption import cfrags
from encryption import ciphertext, capsule, plaintext


bob_cleartext = pre.decrypt_reencrypted(
    receiving_sk=bobs_secret_key,
    delegating_pk=alices_public_key,
    capsule=capsule,
    verified_cfrags=cfrags,
    ciphertext=ciphertext,
)
assert bob_cleartext == plaintext
