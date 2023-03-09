from base64 import b64decode, b64encode
from datetime import datetime
import struct
from typing import Tuple

from umbral import Capsule, PublicKey, VerifiedKeyFrag, VerifiedCapsuleFrag


def datetime_to_challenge(dt: datetime) -> Tuple[str, str]:
    """Process a datetime to get data for the challenge

    Args:
        dt: Datetime to convert

    Returns:
        The datetime as a string
        The datetime coded in base64

    """
    sdt = dt.isoformat()
    b64_hash = b64encode(sdt.encode(encoding="ascii")).decode(encoding="ascii")
    return sdt, b64_hash


def challenge_to_datetime(b64_hash: str) -> dict:
    """Process the base64 data of a challenge to get the original datetime object and its string represntation

    Args:
        b64_hash: base64 data of the challenge

    Returns:
        The datetime as a string
        The datetime object

    """
    try:
        bdt = b64decode(b64_hash.encode(encoding="ascii"))
        sdt = bdt.decode(encoding="ascii")

        dt = datetime.fromisoformat(sdt)

        res = {"status": 200, "iso": sdt, "datetime": dt}

    except BaseException as e:
        res = {"status": 401, "message": "Impossible to get timestamp from challenge"}

    return res


def db_bytes_to_kfrag(db_data: str) -> VerifiedKeyFrag:
    """Build a `VerifiedKeyFrag` from the database string

    Args:
        db_data: kfrag as stored in the database

    Returns:
        The verified kfrag

    """
    dat = b64decode(db_data.encode(encoding="ascii"))

    (kfrag_sze,) = struct.unpack_from("<I", dat, offset=0)
    kfrag_bytes = dat[4 : 4 + kfrag_sze]

    kfrag = VerifiedKeyFrag.from_verified_bytes(kfrag_bytes)

    return kfrag


def db_bytes_to_cfrag(db_data: str) -> VerifiedCapsuleFrag:
    """Build a `VerifiedCapsuleFrag` from the database string

    Args:
        db_data: cfrag as stored in the database

    Returns:
        The verified cfrag

    """
    dat = b64decode(db_data.encode(encoding="ascii"))

    (cfrag_sze,) = struct.unpack_from("<I", dat, offset=0)
    cfrag_bytes = dat[4 : 4 + cfrag_sze]

    cfrag = VerifiedCapsuleFrag.from_verified_bytes(cfrag_bytes)

    return cfrag


def cfrag_to_json(cfrag: VerifiedCapsuleFrag) -> dict:
    """Codes a `VerifiedCapsuleFrag` for write in the database

    Args:
        cfrag: The verified cfrag to store in the database

    Returns:
        A dictionary with key 'cfrag' and the db value as a string

    """
    cfrag_bytes = bytes(cfrag)
    cfrag_sze = len(cfrag_bytes)

    dat = struct.pack(
        "<I" + cfrag_sze * "B",
        cfrag_sze,
        *cfrag_bytes,
    )
    b64data = b64encode(dat).decode(encoding="ascii")

    return {"cfrag": b64data}


def kfrag_to_json(kfrag: VerifiedKeyFrag) -> dict:
    """Codes a `VerifiedKeyFrag` for write in the database

    Args:
        kfrag: The verified kfrag to store in the database

    Returns:
        A dictionary with key 'kfrag' and the db value as a string

    """
    kfrag_bytes = bytes(kfrag)
    kfrag_sze = len(kfrag_bytes)

    dat = struct.pack(
        "<I" + kfrag_sze * "B",
        kfrag_sze,
        *kfrag_bytes,
    )
    b64data = b64encode(dat).decode(encoding="ascii")
    return {"kfrag": b64data}


def encrypted_to_json(capsule: Capsule, ciphertext: bytes) -> dict:
    """Codes an encrypted for write in the database

    Args:
        capsule: The capsule of the encrypted message
        ciphertext: The encrypted messages bytes

    Returns:
        A dictionary with key 'encrypted_data' and the db value as a string

    """
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
    return {
        "encrypted_data": b64data,
    }


def db_bytes_to_encrypted(db_data: str) -> Tuple[Capsule, bytes]:
    """Decodes an encrypted message as stored in the database

    Args:
        db_data: The database representation of the message

    Returns:
        The capsule of the encrypted message
        The encrypted messages bytes

    """
    b64data = db_data.encode(encoding="ascii")
    dat = b64decode(b64data)

    (caps_sze,) = struct.unpack_from("<I", dat, offset=0)
    caps_bytes = dat[4 : 4 + caps_sze]
    (ciph_sze,) = struct.unpack_from("<I", dat, offset=4 + caps_sze)
    ciphertext = dat[4 + caps_sze + 4 : 4 + caps_sze + 4 + ciph_sze]

    capsule = Capsule.from_bytes(caps_bytes)

    return capsule, ciphertext


def encodeKey(pkey: PublicKey) -> str:
    """Encodes a `PublicKey` as a database string

    Args:
        pkey: The database representation of the message

    Returns:
        The database representation of the key

    """
    pkey_bytes = b64encode(bytes(pkey)).decode(encoding="ascii")

    return pkey_bytes


def decodeKey(db_key: str) -> PublicKey:
    """Decodes a `PublicKey` from its database string

    Args:
        db_key: The database representation of the key

    Returns:
        The database representation of the message

    """
    key_bytes = b64decode(db_key.encode(encoding="ascii"))
    key = PublicKey.from_bytes(key_bytes)

    return key
