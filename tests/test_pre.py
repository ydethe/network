import os
from pathlib import Path

import requests
from sqlalchemy import create_engine

from network.User import User
from network.Proxy import Proxy
from network import models


def prepare_test():
    db_uri = os.environ.get("DATABASE_URI", "tests/test_data.db")

    default_db_uri = Path("tests/test_data.db")
    if default_db_uri.exists():
        default_db_uri.unlink()

    engine = create_engine(db_uri, echo=False)
    target_metadata = models.Base.metadata
    target_metadata.create_all(engine)

    alice = User.createUser(config_file=Path("alice.key"))
    bob = User.createUser(config_file=Path("bob.key"))

    ref_plaintext = "Président de la République Française"
    capsule, ciphertext = alice.encrypt(ref_plaintext.encode())

    data = models.PersonData(
        user_id=alice.id,
        person_id=1,
        data_type="name",
        encrypted_data=alice.encrypted_to_db_bytes(capsule, ciphertext),
    )

    with models.con() as session:
        session.add(data)
        session.commit()

    return ref_plaintext


def test_legacy():
    alice = User(config_file=Path("alice.key"))

    # ===================================
    # Alice prepares her message to send
    # ===================================
    original_text = b"Je suis un poney"
    capsule, ciphertext = alice.encrypt(original_text)
    alice_cleartext = alice.decrypt(capsule, ciphertext)
    assert alice_cleartext == original_text


def test_person_data(ref_plaintext: str):
    alice = User(config_file=Path("alice.key"))

    challenge_str = alice.build_challenge()
    r = requests.get(
        f"http://localhost:3034/person/{alice.id}", headers={"Challenge": challenge_str}
    )
    if r.status_code != 200:
        print(r.text)
        return

    data = r.json()

    capsule, ciphertext = alice.db_bytes_to_encrypted(data["encrypted_data"])

    plaintext = alice.decrypt(capsule, ciphertext)

    assert ref_plaintext == plaintext.decode()


def test_pre():
    with models.con() as session:
        alice, bob = session.query(models.DbUser).all()

    ursulas = [Proxy() for _ in range(10)]

    # ===================================
    # Alice prepares her message to send
    # ===================================
    original_text = b"Je suis un poney"
    capsule, ciphertext = alice.encrypt(original_text)
    kfrags = alice.generate_kfrags(bob.public_key, threshold=10, shares=10)

    # ===================================
    # The proxies perform reencryption
    # ===================================
    # Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
    cfrags = list()  # Bob's cfrag collection
    for u, kfrag in zip(ursulas, kfrags):
        cfrag = u.reencrypt(capsule, kfrag)
        cfrags.append(cfrag)  # Bob collects a cfrag

    # =====================================
    # Bob decrypts the reencrypted message
    # =====================================
    bob_cleartext = bob.decrypt_reencrypted(alice.public_key, cfrags, capsule, ciphertext)
    assert bob_cleartext == original_text


ref_plaintext = prepare_test()
# test_legacy()
test_person_data(ref_plaintext=ref_plaintext)
# test_pre()
