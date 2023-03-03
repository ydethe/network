from umbral import generate_kfrags

from key_generation import alices_signer, alices_secret_key, bobs_public_key


# Alice generates "M of N" re-encryption key fragments (or "KFrags") for Bob.
# In this example, 10 out of 20.
kfrags = generate_kfrags(
    delegating_sk=alices_secret_key,
    receiving_pk=bobs_public_key,
    signer=alices_signer,
    threshold=1,
    shares=1,
)
