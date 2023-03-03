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
        self.__secret_key = SecretKey.random()
        self.public_key = self.__secret_key.public_key()
        self.__signing_key = SecretKey.random()
        self.verifying_key = self.__signing_key.public_key()

    def print_keys(self):
        print(self.name)
        print("Secret", b"***")
        print("Public", bytes(self.public_key))
        print("Signing", b"***")
        print("Verifying", bytes(self.verifying_key))

    def encrypt(self, plaintext: bytes) -> Tuple[Capsule, bytes]:
        capsule, ciphertext = encrypt(self.public_key, plaintext)
        return capsule, ciphertext

    def decrypt(self, capsule: Capsule, ciphertext: bytes) -> bytes:
        cleartext = decrypt_original(self.__secret_key, capsule, ciphertext)
        return cleartext

    def generate_kfrags(
        self, receiver: "User", threshold: int, shares: int
    ) -> List[VerifiedKeyFrag]:
        signer = Signer(self.__signing_key)
        kfrags = generate_kfrags(
            delegating_sk=self.__secret_key,
            receiving_pk=receiver.public_key,
            signer=signer,
            threshold=threshold,
            shares=shares,
        )
        return kfrags

    def decrypt_reencrypted(
        self,
        emitter: "User",
        cfrags: List[VerifiedCapsuleFrag],
        capsule: Capsule,
        ciphertext: bytes,
    ) -> bytes:
        cleartext = pre.decrypt_reencrypted(
            receiving_sk=self.__secret_key,
            delegating_pk=emitter.public_key,
            verified_cfrags=cfrags,
            capsule=capsule,
            ciphertext=ciphertext,
        )
        return cleartext
