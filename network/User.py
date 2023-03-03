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
    """User that can encrypt / decrypt messages, and delegate content decryption to other users

    Args:
        name: Name of the user

    """

    def __init__(self, name):
        self.name = name

        # Key pair for encryption
        self.__secret_key = SecretKey.random()
        self.public_key = self.__secret_key.public_key()

        # Key pair for authentication
        self.__signing_key = SecretKey.random()
        self.verifying_key = self.__signing_key.public_key()

    def encrypt(self, plaintext: bytes) -> Tuple[Capsule, bytes]:
        """Encrypt a message

        Args:
            plaintext: Clear content. Ca be anything

        Returns:
            The capsule
            The ciphertext

        """
        capsule, ciphertext = encrypt(self.public_key, plaintext)
        return capsule, ciphertext

    def decrypt(self, capsule: Capsule, ciphertext: bytes) -> bytes:
        """Decrypt a message

        Args:
            capsule: The capsule returnd by the encrypt method
            ciphertext: The ciphertext returnd by the encrypt method

        Returns:
            The plaintext message

        """
        cleartext = decrypt_original(self.__secret_key, capsule, ciphertext)
        return cleartext

    def generate_kfrags(
        self, receiver: "User", threshold: int, shares: int
    ) -> List[VerifiedKeyFrag]:
        """Generate "M of N" re-encryption key fragments (or "KFrags") for the receiver

        Args:
            receiver: The receiver allowed to decrypt the ciphertext
            threshold: The number of VerifiedCapsuleFrag necessary to decrypt the mesage
            shares: Total number of VerifiedCapsuleFrag generated

        Returns:
            A list of kfrags

        """
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
        """Decrypt the message sent by another User

        Args:
            emitter: The emitter that sent the message
            cfrags: List of VerifiedCapsuleFrag generated by the proxies
            capsule: The capsule returnd by the encrypt method
            ciphertext: The ciphertext returnd by the encrypt method

        Returns:
            The plaintext message

        """
        cleartext = pre.decrypt_reencrypted(
            receiving_sk=self.__secret_key,
            delegating_pk=emitter.public_key,
            verified_cfrags=cfrags,
            capsule=capsule,
            ciphertext=ciphertext,
        )
        return cleartext
