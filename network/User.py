from typing import List, Tuple
from umbral import (
    VerifiedCapsuleFrag,
    VerifiedKeyFrag,
    PublicKey,
    generate_kfrags,
    encrypt,
    SecretKey,
    Signer,
    decrypt_original,
    pre,
)
from umbral.capsule import Capsule


class User(object):
    def __init__(self, name):
        self.name = name
        self.secret_key = SecretKey.random()
        self.public_key = self.secret_key.public_key()
        self.signing_key = SecretKey.random()
        self.verifying_key = self.signing_key.public_key()

    def print_keys(self):
        print(self.name)
        print("Secret", self.secret_key.to_secret_bytes())
        print("Public", bytes(self.public_key))
        print("Signing", self.signing_key.to_secret_bytes())
        print("Verifying", bytes(self.verifying_key))

    def encrypt(self, plaintext: bytes) -> Tuple[Capsule, bytes]:
        capsule, ciphertext = encrypt(self.public_key, plaintext)
        return capsule, ciphertext

    def decrypt(self, capsule: Capsule, ciphertext: bytes) -> bytes:
        cleartext = decrypt_original(self.secret_key, capsule, ciphertext)
        return cleartext

    def generate_kfrags(
        self, rx_pub_key: PublicKey, threshold: int, shares: int
    ) -> List[VerifiedKeyFrag]:
        signer = Signer(self.signing_key)
        kfrags = generate_kfrags(
            delegating_sk=self.secret_key,
            receiving_pk=rx_pub_key,
            signer=signer,
            threshold=threshold,
            shares=shares,
        )
        return kfrags

    def decrypt_reencrypted(
        self,
        tx_public_key: PublicKey,
        cfrags: List[VerifiedCapsuleFrag],
        capsule: Capsule,
        ciphertext: bytes,
    ) -> bytes:
        cleartext = pre.decrypt_reencrypted(
            receiving_sk=self.secret_key,
            delegating_pk=tx_public_key,
            verified_cfrags=cfrags,
            capsule=capsule,
            ciphertext=ciphertext,
        )
        return cleartext
