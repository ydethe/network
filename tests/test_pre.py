import os
from pathlib import Path
import time

from sqlalchemy import create_engine
from fastapi.testclient import TestClient

from network.frontend.User import User
from network.backend.Proxy import Proxy
from network.backend import models
from network.backend.main import app
from network.transcoding import db_bytes_to_encrypted
from network.schemas import PersonDataModel


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

    data = alice.encrypt_for_db(ref_plaintext.encode())

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
    u_item = alice.encrypt(original_text)
    alice_cleartext = alice.decrypt(u_item)
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

    plaintext = alice.decrypt_from_db(r.json())

    assert ref_plaintext == plaintext.decode()


def test_pre(ref_plaintext: str = "Président de la République Française"):
    client = TestClient(app)

    alice = User(config_file=Path("alice.topsecret"))
    bob = User(config_file=Path("bob.topsecret"))

    # ===================================
    # Alice prepares her message to send
    # ===================================
    # Only Alice can generate kfrags
    kfrags = alice.generate_kfrags(bob.public_key, threshold=1, shares=1)
    kfrag_json = alice.kfrag_to_db_bytes(kfrags[0])

    challenge_str = alice.build_challenge()

    # We send data for the first person in alice's list
    r = client.get("/person/", headers={"Challenge": challenge_str})
    persons_list = r.json()
    person_id = persons_list[0]

    # Actual sending
    r = client.post(
        f"/pre/{person_id}/{bob.id}", headers={"Challenge": challenge_str}, json=kfrag_json
    )
    assert r.status_code == 200
    item = r.json()
    assert item["cfrag"] != ""
    assert item["sender_pkey"] != ""
    assert item["encrypted_data"] != ""
    bob_person_id = item["id"]

    # =====================================
    # Bob decrypts the reencrypted message
    # =====================================
    # bob_cleartext = bob.decrypt_reencrypted(alice.public_key, cfrags, capsule, ciphertext)
    # assert bob_cleartext == original_text
    challenge_str = bob.build_challenge()
    r = client.get(f"/person/{bob_person_id}", headers={"Challenge": challenge_str})

    data = r.json()
    item = PersonDataModel(**data)
    u_item = item.toUmbral()

    plaintext = bob.decrypt(u_item)

    assert ref_plaintext == plaintext.decode()


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
    # test_errors()
