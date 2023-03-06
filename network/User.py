from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Tuple
import struct
from base64 import b64encode, b64decode

from umbral import (
    Signature,
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
from umbral.hashing import Hash

from .models import DbUser, con


class User(object):
    @classmethod
    def createUser(cls, file_pref: str = ""):
        # Key for encryption
        private_key = SecretKey.random()
        cls.saveKeyToFile(private_key, Path(f"{file_pref}private.key"))

        # Key for authentication
        signing_key = SecretKey.random()
        cls.saveKeyToFile(signing_key, Path(f"{file_pref}signing.key"))

        db_pkey = b64encode(bytes(private_key.public_key())).decode(encoding="ascii")
        db_vkey = b64encode(bytes(signing_key.public_key())).decode(encoding="ascii")

        db_user = DbUser(public_key=db_pkey, verifying_key=db_vkey)
        with con() as session:
            session.add(db_user)
            session.commit()
            session.refresh(db_user)

        res = cls(user_id=db_user.id, file_pref=file_pref, db_user=db_user)

        return res

    @classmethod
    def saveKeyToFile(cls, key: SecretKey, path: Path):
        with open(path, "wb") as f:
            f.write(key.to_secret_bytes())

    @classmethod
    def loadKeyFromFile(cls, path: Path) -> SecretKey:
        with open(path, "rb") as f:
            key_bytes = f.read()
        key = SecretKey.from_bytes(key_bytes)
        return key

    def __init__(self, user_id: int, file_pref: str = "", db_user: DbUser = None):
        self.private_key = self.loadKeyFromFile(Path(f"{file_pref}private.key"))
        self.public_key = self.private_key.public_key()

        self.signing_key = self.loadKeyFromFile(Path(f"{file_pref}signing.key"))
        self.verifying_key = self.signing_key.public_key()

        self.id = user_id

        if db_user is None:
            with con() as session:
                db_user: DbUser = session.query(DbUser).filter(DbUser.id == user_id).first()

        db_pkey, db_vkey = db_user.decodeKeys()

        if bytes(db_pkey) != bytes(self.public_key):
            raise AssertionError(f"Corrupted public key")

        if bytes(db_vkey) != bytes(self.verifying_key):
            raise AssertionError(f"Corrupted verifying key")

    def build_challenge(self) -> str:
        sdt = datetime.now().isoformat()
        hash = Hash()
        hash.update(sdt.encode(encoding="ascii"))

        signer = Signer(self.signing_key)
        signature = signer.sign_digest(hash)

        b64_hash = b64encode(sdt.encode(encoding="ascii")).decode(encoding="ascii")
        b64_sign = b64encode(bytes(signature)).decode(encoding="ascii")

        return f"{self.id}:{b64_hash}:{b64_sign}"

    def encrypt(self, plaintext: bytes) -> Tuple[Capsule, bytes]:
        """Encrypt a message

        Args:
            plaintext: Clear content. Ca be anything

        Returns:
            The encapsulated symmetric key use to encrypt it
            The ciphertext

        """
        public_key = self.private_key.public_key()
        capsule, ciphertext = encrypt(public_key, plaintext)

        return capsule, ciphertext

    def encrypted_to_db_bytes(self, capsule: Capsule, ciphertext: bytes) -> str:
        caps_sze = capsule.serialized_size()
        ciph_sze = len(ciphertext)

        dat = struct.pack(
            "<I" + caps_sze * "B" + "I" + ciph_sze * "B",
            caps_sze,
            *bytes(capsule),
            ciph_sze,
            *ciphertext,
        )
        b64data = b64encode(dat).decode(encoding="ascii")
        return b64data

    def db_bytes_to_encrypted(self, b64data: str) -> Tuple[Capsule, bytes]:
        dat = b64decode(b64data.encode(encoding="ascii"))
        (caps_sze,) = struct.unpack_from("<I", dat, offset=0)
        (ciph_sze,) = struct.unpack_from("<I", dat, offset=4 + caps_sze)
        caps_bytes = dat[4 : 4 + caps_sze]
        ciphertext = dat[8 + caps_sze : 8 + caps_sze + ciph_sze]

        capsule = Capsule.from_bytes(caps_bytes)

        return capsule, ciphertext

    def decrypt(self, capsule: Capsule, ciphertext: bytes) -> bytes:
        """Decrypt a message

        Args:
            capsule: The encapsulated symmetric key returnd by the encrypt method
            ciphertext: The ciphertext returnd by the encrypt method

        Returns:
            The plaintext message

        """
        cleartext = decrypt_original(self.private_key, capsule, ciphertext)
        return cleartext

    def generate_kfrags(
        self, rx_public_key: PublicKey, threshold: int, shares: int
    ) -> List[VerifiedKeyFrag]:
        """Generate "M of N" re-encryption key fragments (or "KFrags") for the receiver

        Args:
            rx_public_key: The public key of the receiver
            threshold: The number of VerifiedCapsuleFrag necessary to decrypt the mesage
            shares: Total number of VerifiedCapsuleFrag generated

        Returns:
            A list of kfrags

        """
        signer = Signer(self.signing_key)
        kfrags = generate_kfrags(
            delegating_sk=self.private_key,
            receiving_pk=rx_public_key,
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
        """Decrypt the message sent by another User

        Args:
            tx_public_key: The public key of the sender
            cfrags: List of VerifiedCapsuleFrag generated by the proxies
            capsule: The encapsulated symmetric key returnd by the encrypt method
            ciphertext: The ciphertext returnd by the encrypt method

        Returns:
            The plaintext message

        """
        cleartext = pre.decrypt_reencrypted(
            receiving_sk=self.private_key,
            delegating_pk=tx_public_key,
            verified_cfrags=cfrags,
            capsule=capsule,
            ciphertext=ciphertext,
        )
        return cleartext
