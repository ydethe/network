from pathlib import Path
from umbral import PublicKey
from sqlalchemy import create_engine

from network.User import User
from network.Proxy import Proxy
from network import models


def prepare_test():
    db_url = Path("tests/test_data.db")
    if db_url.exists():
        db_url.unlink()
    engine = create_engine(f"sqlite:///{db_url}", echo=False)
    target_metadata = models.Base.metadata
    target_metadata.create_all(engine)

    alice = models.DbUser.createUser()
    bob = models.DbUser.createUser()

    with models.con() as session:
        session.add(alice)
        session.add(bob)
        session.commit()


def test_legacy():
    with models.con() as session:
        db_user = session.query(models.DbUser).first()
        alice = User.fromDatabaseUser(db_user)

    # ===================================
    # Alice prepares her message to send
    # ===================================
    original_text = b"Je suis un poney"
    capsule, ciphertext = alice.encrypt(original_text)
    alice_cleartext = alice.decrypt(capsule, ciphertext)
    assert alice_cleartext == original_text


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


prepare_test()
test_legacy()
# test_pre()
