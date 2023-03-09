import logging
from pathlib import Path
from datetime import datetime
from typing import List
import struct
from base64 import b64encode

import requests
from umbral import (
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

from ..transcoding import datetime_to_challenge, encodeKey, encrypted_to_json, kfrag_to_json
from .. import schemas


class User(object):
    """Creates a user, without writing it in the database. Only the keys are stored.

    Args:
        config_file: File to read to instanciate the user

    """

    def __init__(self, server_url: str, config_file: Path = None):
        logger = logging.getLogger(f"{__package__}_logger")

        self.server_url = server_url

        if config_file is None or not config_file.exists():
            # Key for encryption
            self.private_key = SecretKey.random()
            self.public_key = self.private_key.public_key()

            # Key for authentication
            self.signing_key = SecretKey.random()
            self.verifying_key = self.signing_key.public_key()

            r = requests.post(f"{self.server_url}/users/", json=self.to_json())
            assert r.status_code == 200
            self.id = r.json()["id"]

            logger.info(f"Created user id={self.id}")

        else:
            with open(config_file.expanduser().resolve(), "rb") as f:
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

            logger.info(f"Loaded user id={self.id}")

    def to_json(self) -> dict:
        """Seralize the user for record it in the database

        The keys are :

        * id: Set to None because handled by the database
        * public_key: The public key as database string
        * verifying_key: The verifying_key key as database string
        * time_created: Set to None because handled by the database
        * time_updated: Set to None because handled by the database

        Returns:
            The dictonary for the database

        """
        pkey = encodeKey(self.public_key)
        vkey = encodeKey(self.verifying_key)

        return {
            "id": None,
            "public_key": pkey,
            "verifying_key": vkey,
            "time_created": None,
            "time_updated": None,
        }

    def writeConfigurationFile(self, path: Path):
        """Save user's information in a top secret file

        Args:
            path: Path where the data should be written. Shall have a .topsecret extension

        """
        if self.id is None:
            raise AssertionError(
                "User not registered in database. Cannot write the .topsecret file"
            )

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
        with open(path.expanduser().resolve(), "wb") as f:
            f.write(dat)

    def build_challenge(self) -> str:
        """Build a string that can be sent as auth challenge to the server

        Returns:
            A challenge

        """
        if self.id is None:
            raise AssertionError(
                "User not registered in database. Cannot write the .topsecret file"
            )

        dt = datetime.now()
        sdt, b64_hash = datetime_to_challenge(dt)

        hash = Hash()
        hash.update(sdt.encode(encoding="ascii"))

        signer = Signer(self.signing_key)
        signature = signer.sign_digest(hash)

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
        if self.id is None:
            raise AssertionError(
                "User not registered in database. Cannot write the .topsecret file"
            )

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
            A dictionary with key 'encrypted_data' and the db value as a string

        """
        u_item = self.encrypt(plaintext)
        msg = encrypted_to_json(u_item.capsule, u_item.ciphertext)
        return msg

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
        item = schemas.ItemModel(**db_data)
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

    def generate_kfrags_for_db(self, rx_public_key: PublicKey) -> dict:
        """Generate "M of N" re-encryption key fragments (or "KFrags") for the receiver

        Args:
            rx_public_key: The public key of the receiver

        Returns:
            A dictionary with key 'kfrag' and the db value as a string

        """
        kfrags = self.generate_kfrags(rx_public_key, threshold=1, shares=1)
        kfrag_json = kfrag_to_json(kfrags[0])
        return kfrag_json

    def saveItemInDatabase(self, item: bytes) -> int:
        data = self.encrypt_for_db(item)

        challenge_str = self.build_challenge()
        r = requests.post(
            f"{self.server_url}/item/", json=data, headers={"Challenge": challenge_str}
        )
        assert r.status_code == 200
        data = r.json()

        return data["id"]

    def loadItemFromDatabase(self, item_id: int) -> bytes:
        challenge_str = self.build_challenge()
        r = requests.get(f"{self.server_url}/item/{item_id}", headers={"Challenge": challenge_str})
        if r.status_code != 200:
            raise AssertionError(r.json()["detail"])

        data = r.json()
        data = self.decrypt_from_db(data)

        return data
