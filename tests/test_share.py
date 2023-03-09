import sys
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

from network.frontend.User import User
from network.backend.main import app
from network.schemas import ItemModel

sys.path.insert(0, str(Path(__file__).parent))
from prepare import prepare_database


class TestShare(unittest.TestCase):
    @classmethod
    def setUpClass(cls, ref_plaintext: str = "Président de la République Française"):
        cls.ref_plaintext = ref_plaintext
        prepare_database(ref_plaintext)

    def test_legacy(self):
        alice = User(config_file=Path("tests/alice.topsecret"))

        # ===================================
        # Alice prepares her message to send
        # ===================================
        original_text = b"Je suis un poney"
        u_item = alice.encrypt(original_text)
        alice_cleartext = alice.decrypt(u_item)
        assert alice_cleartext == original_text

    def test_share(self):
        client = TestClient(app)

        alice = User(config_file=Path("tests/alice.topsecret"))
        bob = User(config_file=Path("tests/bob.topsecret"))

        # ===================================
        # Alice prepares her message to send
        # ===================================
        # Only Alice can generate kfrags
        kfrag_json = alice.generate_kfrags_for_db(bob.public_key)

        # We send data for the first item in alice's list
        challenge_str = alice.build_challenge()
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 200
        items_list = r.json()
        item_id = items_list[0]

        # Actual sending
        challenge_str = alice.build_challenge()
        r = client.post(
            f"/share/{item_id}/{bob.id}", headers={"Challenge": challenge_str}, json=kfrag_json
        )
        assert r.status_code == 200
        item = r.json()
        assert item["cfrag"] != ""
        assert item["sender_pkey"] != ""
        assert item["encrypted_data"] != ""
        bob_item_id = item["id"]

        # =====================================
        # Bob decrypts the reencrypted message
        # =====================================
        # bob_cleartext = bob.decrypt_reencrypted(alice.public_key, cfrags, capsule, ciphertext)
        # assert bob_cleartext == original_text
        challenge_str = bob.build_challenge()
        r = client.get(f"/item/{bob_item_id}", headers={"Challenge": challenge_str})
        assert r.status_code == 200

        data = r.json()
        item = ItemModel(**data)
        u_item = item.toUmbral()

        plaintext = bob.decrypt(u_item)

        assert TestShare.ref_plaintext == plaintext.decode()

    def test_share_errors(self):
        client = TestClient(app)

        alice = User(config_file=Path("tests/alice.topsecret"))
        bob = User(config_file=Path("tests/bob.topsecret"))

        # ===================================
        # Alice prepares her message to send
        # ===================================
        # Only Alice can generate kfrags
        kfrag_json = alice.generate_kfrags_for_db(bob.public_key)

        # Actual sending of an item that does not exist
        item_id = 46435434
        challenge_str = alice.build_challenge()
        r = client.post(
            f"/share/{item_id}/{bob.id}", headers={"Challenge": challenge_str}, json=kfrag_json
        )
        assert r.status_code == 404
        assert f"Item {item_id} not found" in r.json()["detail"]

        # We send data for the first item in alice's list
        challenge_str = alice.build_challenge()
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 200
        items_list = r.json()
        item_id = items_list[0]

        # Actual sending to a user that does not exist
        recipient_id = 46435434
        challenge_str = alice.build_challenge()
        r = client.post(
            f"/share/{item_id}/{recipient_id}",
            headers={"Challenge": challenge_str},
            json=kfrag_json,
        )
        assert r.status_code == 404
        assert f"Recipient user {recipient_id} not found" in r.json()["detail"]


if __name__ == "__main__":
    TestShare.setUpClass()
    a = TestShare()
    # a.test_legacy()
    a.test_share()
