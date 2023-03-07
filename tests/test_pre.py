import os
from pathlib import Path
import time

from sqlalchemy import create_engine
from fastapi.testclient import TestClient

from network.frontend.User import User
from network.frontend.Proxy import Proxy
from network.backend import models
from network.backend.main import app


def test_prepare(ref_plaintext: str = "Président de la République Française"):
    db_uri = os.environ.get("DATABASE_URI", "sqlite:///tests/test_data.db")

    default_db_uri = Path("tests/test_data.db")
    if default_db_uri.exists():
        default_db_uri.unlink()

    engine = create_engine(db_uri, echo=False)
    target_metadata = models.Base.metadata
    target_metadata.create_all(engine)

    client = TestClient(app)

    alice: User = User.createUser()
    r = client.post("/users/", json=alice.to_json())
    alice.id = r.json()["id"]
    alice.writeConfigurationFile(Path("alice.topsecret"))

    bob: User = User.createUser()
    r = client.post("/users/", json=bob.to_json())
    bob.id = r.json()["id"]
    bob.writeConfigurationFile(Path("bob.topsecret"))

    capsule, ciphertext = alice.encrypt(ref_plaintext.encode())

    data = {
        "encrypted_data": alice.encrypted_to_db_bytes(capsule, ciphertext),
    }

    challenge_str = alice.build_challenge()
    r = client.post("/person/", json=data, headers={"Challenge": challenge_str})
    data = r.json()

    assert data["user_id"] == alice.id


def test_legacy():
    alice = User(config_file=Path("alice.topsecret"))

    # ===================================
    # Alice prepares her message to send
    # ===================================
    original_text = b"Je suis un poney"
    capsule, ciphertext = alice.encrypt(original_text)
    alice_cleartext = alice.decrypt(capsule, ciphertext)
    assert alice_cleartext == original_text


def test_person_data(ref_plaintext: str = "Président de la République Française"):
    client = TestClient(app)

    alice = User(config_file=Path("alice.topsecret"))

    challenge_str = alice.build_challenge()
    r = client.get("/person/", headers={"Challenge": challenge_str})
    if r.status_code != 200:
        print(r.text)
        return

    data = r.json()
    person_id = data[0]

    r = client.get(f"/person/{person_id}", headers={"Challenge": challenge_str})
    if r.status_code != 200:
        print(r.text)
        return

    data = r.json()

    capsule, ciphertext = alice.db_bytes_to_encrypted(data["encrypted_data"])

    plaintext = alice.decrypt(capsule, ciphertext)

    assert ref_plaintext == plaintext.decode()


def test_pre():
    alice = User(config_file=Path("alice.topsecret"))
    bob = User(config_file=Path("bob.topsecret"))

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


def test_errors():
    client = TestClient(app)

    alice = User(config_file=Path("alice.topsecret"))

    r = client.get("/person/")
    assert r.status_code == 401
    assert r.json()["detail"] == "No challenge provided with the request"

    r = client.get("/person/", headers={"Challenge": "false"})
    assert r.status_code == 401
    assert (
        "Invalid format for challenge. Shall be <user_id>:<b64_hash>:<b64_sign>"
        in r.json()["detail"]
    )

    challenge_str = alice.build_challenge()
    time.sleep(6)
    r = client.get("/person/", headers={"Challenge": challenge_str})
    assert r.status_code == 401
    assert "Failed solving the challenge" in r.json()["detail"]


if __name__ == "__main__":
    ref_plaintext = "Président de la République Française"

    test_prepare(ref_plaintext)
    # test_legacy()
    # test_person_data(ref_plaintext)
    # test_pre()
    test_errors()
