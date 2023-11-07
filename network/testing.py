import os
from pathlib import Path

from sqlalchemy import create_engine
from fastapi.testclient import TestClient

from network.frontend.User import User
from network.backend import models
from network.backend.main import app


def prepare_database(ref_plaintext: str = "Président de la République Française"):
    db_uri = os.environ.get("DATABASE_URI", "sqlite:///tests/test_data.db")

    default_db_uri = Path("tests/test_data.db")
    if default_db_uri.exists():
        default_db_uri.unlink()

    engine = create_engine(db_uri, echo=False)
    target_metadata = models.Base.metadata
    target_metadata.create_all(engine)

    admin = User()
    data = admin.to_json()
    db_admin = models.DbUser(
        admin=True, public_key=data["public_key"], verifying_key=data["verifying_key"]
    )
    con = models.get_connection()
    with con() as session:
        session.add(db_admin)
        session.commit()
        session.refresh(db_admin)
        admin.id = db_admin.id
    admin.to_topsecret_file(Path("tests/admin.topsecret"))

    client = TestClient(app)

    alice = User()
    challenge_str = admin.build_challenge()
    r = client.post("/users/", json=alice.to_json(), headers={"Challenge": challenge_str})
    assert r.status_code == 200
    alice.id = r.json()["id"]
    alice.to_topsecret_file(Path("tests/alice.topsecret"))

    bob = User()
    challenge_str = admin.build_challenge()
    r = client.post("/users/", json=bob.to_json(), headers={"Challenge": challenge_str})
    assert r.status_code == 200
    bob.id = r.json()["id"]
    bob.to_topsecret_file(Path("tests/bob.topsecret"))

    data = alice.encrypt_for_db(ref_plaintext.encode())

    challenge_str = alice.build_challenge()
    r = client.post("/item/", json=data, headers={"Challenge": challenge_str})
    assert r.status_code == 200
    data = r.json()

    assert data["user_id"] == alice.id
