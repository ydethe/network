from base64 import b64decode, b64encode
from datetime import datetime
import struct
from typing import Tuple

from umbral import Capsule, PublicKey, VerifiedKeyFrag, VerifiedCapsuleFrag


def datetime_to_challenge(dt: datetime) -> Tuple[str, str]:
    sdt = dt.isoformat()
    b64_hash = b64encode(sdt.encode(encoding="ascii")).decode(encoding="ascii")
    return sdt, b64_hash


def challenge_to_datetime(b64_hash: str) -> Tuple[str, datetime]:
    bdt = b64decode(b64_hash.encode(encoding="ascii"))
    sdt = bdt.decode(encoding="ascii")

    dt = datetime.fromisoformat(sdt)

    return sdt, dt


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


def cfrag_to_db_bytes(cfrag: VerifiedCapsuleFrag) -> dict:
    cfrag_bytes = bytes(cfrag)
    cfrag_sze = len(cfrag_bytes)

    dat = struct.pack(
        "<I" + cfrag_sze * "B",
        cfrag_sze,
        *cfrag_bytes,
    )
    b64data = b64encode(dat).decode(encoding="ascii")

    return {"cfrag": b64data}


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
