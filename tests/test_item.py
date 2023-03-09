import sys
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

from network.frontend.User import User
from network.backend.main import app

sys.path.insert(0, str(Path(__file__).parent))
from prepare import prepare_database


class TestItem(unittest.TestCase):
    @classmethod
    def setUpClass(cls, ref_plaintext: str = "Président de la République Française"):
        cls.ref_plaintext = ref_plaintext
        prepare_database(ref_plaintext)

    def test_item_data(self):
        client = TestClient(app)

        alice = User(config_file=Path("tests/alice.topsecret"))

        challenge_str = alice.build_challenge()
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 200
        data = r.json()
        item_id = data[0]

        challenge_str = alice.build_challenge()
        r = client.get(f"/item/{item_id}", headers={"Challenge": challenge_str})
        assert r.status_code == 200

        plaintext = alice.decrypt_from_db(r.json())

        assert TestItem.ref_plaintext == plaintext.decode()

    def test_item_errors(self):
        client = TestClient(app)

        alice = User(config_file=Path("tests/alice.topsecret"))

        challenge_str = alice.build_challenge()
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 200
        data = r.json()
        item_id = data[0]

        # Trying to reuse a challenge (forbidden !!!)
        r = client.get(f"/item/{item_id}", headers={"Challenge": challenge_str})
        assert r.status_code == 401
        assert "Trying to reuse a challenge" in r.json()["detail"]

        # Trying to access a non existing item
        challenge_str = alice.build_challenge()
        r = client.get(f"/item/6867474357", headers={"Challenge": challenge_str})
        assert r.status_code == 404
        assert "Person data not found" in r.json()["detail"]


if __name__ == "__main__":
    TestItem.setUpClass()
    a = TestItem()
    a.test_item_data()
