from pathlib import Path
from datetime import datetime
from typing import List, Tuple
import struct
from base64 import b64encode, b64decode

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
from umbral.hashing import Hash

from ..transcoding import encrypted_to_db_bytes
from .. import schemas


class User(object):
    @classmethod
    def createUser(cls) -> "User":
        res = cls(config_file=None)

        # Key for encryption
        res.private_key = SecretKey.random()
        res.public_key = res.private_key.public_key()

        # Key for authentication
        res.signing_key = SecretKey.random()
        res.verifying_key = res.signing_key.public_key()

        return res

    def to_json(self):
        pkey = b64encode(bytes(self.public_key)).decode(encoding="ascii")
        vkey = b64encode(bytes(self.verifying_key)).decode(encoding="ascii")

        return {
            "id": None,
            "public_key": pkey,
            "verifying_key": vkey,
            "time_created": None,
            "time_updated": None,
        }

    def writeConfigurationFile(
        self,
        path: Path = Path("network.topsecret"),
    ):
        pkey = self.private_key.to_secret_bytes()
        skey = self.signing_key.to_secret_bytes()

        fmt = "<II" + len(pkey) * "B" + "I" + len(skey) * "B"
        dat = struct.pack(
            fmt,
            self.id,
            len(pkey),
            *pkey,
            len(skey),
            *skey,
        )
        with open(path, "wb") as f:
            f.write(dat)

    def __init__(self, config_file: Path = Path("network.topsecret")):
        if not config_file is None:
            with open(config_file, "rb") as f:
                dat = f.read()

            user_id, pkey_len = struct.unpack_from("<II", dat, offset=0)
            pkey_bytes = dat[8 : 8 + pkey_len]
            (skey_len,) = struct.unpack_from("<I", dat, offset=8 + pkey_len)
            skey_bytes = dat[8 + pkey_len + 4 : 8 + pkey_len + 4 + skey_len]

            self.private_key = SecretKey.from_bytes(pkey_bytes)
            self.public_key = self.private_key.public_key()

            self.signing_key = SecretKey.from_bytes(skey_bytes)
            self.verifying_key = self.signing_key.public_key()

            self.id = user_id

    def build_challenge(self) -> str:
        sdt = datetime.now().isoformat()
        hash = Hash()
        hash.update(sdt.encode(encoding="ascii"))

        signer = Signer(self.signing_key)
        signature = signer.sign_digest(hash)

        b64_hash = b64encode(sdt.encode(encoding="ascii")).decode(encoding="ascii")
        b64_sign = b64encode(bytes(signature)).decode(encoding="ascii")

        return f"{self.id}:{b64_hash}:{b64_sign}"

    def encrypt(self, plaintext: bytes) -> schemas.UmbralMessage:
        """Encrypt a message

        Args:
            plaintext: Clear content. Ca be anything

        Returns:
            The encapsulated symmetric key use to encrypt it
            The ciphertext

        """
        public_key = self.private_key.public_key()
        capsule, ciphertext = encrypt(public_key, plaintext)

        res = schemas.UmbralMessage(
            user_id=self.id,
            capsule=capsule,
            ciphertext=ciphertext,
        )

        return res

    def encrypt_for_db(self, plaintext: bytes) -> dict:
        """Encrypt a message

        Args:
            plaintext: Clear content. Ca be anything

        Returns:
            The string for the database

        """
        u_item = self.encrypt(plaintext)
        msg = encrypted_to_db_bytes(u_item.capsule, u_item.ciphertext)
        db_data = {
            "encrypted_data": msg,
        }
        return db_data

    def decrypt(self, item: schemas.UmbralMessage) -> bytes:
        """Decrypt a message

        Args:
            item: The message

        Returns:
            The plaintext message

        """
        if item.cfrag is None and item.sender_pkey is None:
            cleartext = decrypt_original(self.private_key, item.capsule, item.ciphertext)
        elif not item.cfrag is None and not item.sender_pkey is None:
            cleartext = pre.decrypt_reencrypted(
                receiving_sk=self.private_key,
                delegating_pk=item.sender_pkey,
                verified_cfrags=[item.cfrag],
                capsule=item.capsule,
                ciphertext=item.ciphertext,
            )
        else:
            raise AssertionError(f"cfrag and sender_pkey shall be simultaneously set or unset")

        return cleartext

    def decrypt_from_db(self, db_data: dict) -> bytes:
        """Decrypt a message

        Args:
            item: The message

        Returns:
            The plaintext message

        """
        item = schemas.PersonDataModel(**db_data)
        u_item = item.toUmbral()
        cleartext = self.decrypt(u_item)
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

    @staticmethod
    def kfrag_to_db_bytes(kfrag: VerifiedKeyFrag) -> dict:
        kfrag_bytes = bytes(kfrag)
        kfrag_sze = len(kfrag_bytes)

        dat = struct.pack(
            "<I" + kfrag_sze * "B",
            kfrag_sze,
            *kfrag_bytes,
        )
        b64data = b64encode(dat).decode(encoding="ascii")
        return {"kfrag": b64data}
