from base64 import b64decode, b64encode
import struct
from typing import Tuple

from umbral import Capsule, PublicKey, VerifiedKeyFrag, VerifiedCapsuleFrag


def db_bytes_to_kfrag(db_data: str) -> VerifiedKeyFrag:
    dat = b64decode(db_data.encode(encoding="ascii"))

    (kfrag_sze,) = struct.unpack_from("<I", dat, offset=0)
    kfrag_bytes = dat[4 : 4 + kfrag_sze]

    kfrag = VerifiedKeyFrag.from_verified_bytes(kfrag_bytes)

    return kfrag


def db_bytes_to_cfrag(db_data: str) -> VerifiedCapsuleFrag:
    dat = b64decode(db_data.encode(encoding="ascii"))

    (cfrag_sze,) = struct.unpack_from("<I", dat, offset=0)
    cfrag_bytes = dat[4 : 4 + cfrag_sze]

    cfrag = VerifiedCapsuleFrag.from_verified_bytes(cfrag_bytes)

    return cfrag


def encrypted_to_db_bytes(capsule: Capsule, ciphertext: bytes) -> str:
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


def db_bytes_to_encrypted(db_data: str) -> Tuple[Capsule, bytes]:
    b64data = db_data.encode(encoding="ascii")
    dat = b64decode(b64data)

    (caps_sze,) = struct.unpack_from("<I", dat, offset=0)
    caps_bytes = dat[4 : 4 + caps_sze]
    (ciph_sze,) = struct.unpack_from("<I", dat, offset=4 + caps_sze)
    ciphertext = dat[4 + caps_sze + 4 : 4 + caps_sze + 4 + ciph_sze]

    capsule = Capsule.from_bytes(caps_bytes)

    return capsule, ciphertext


def encodeKey(pkey: PublicKey) -> str:
    pkey_bytes = b64encode(bytes(pkey)).decode(encoding="ascii")

    return pkey_bytes


def decodeKey(db_key: str) -> PublicKey:
    key_bytes = b64decode(db_key.encode(encoding="ascii"))
    key = PublicKey.from_bytes(key_bytes)

    return key
