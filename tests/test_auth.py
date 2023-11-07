from pathlib import Path
import time
import unittest

from fastapi.testclient import TestClient

from network.backend.auth_depend import challenge_auth
from network.frontend.User import User
from network.backend.main import app
from network.testing import prepare_database


class TestAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls, ref_plaintext: str = "Président de la République Française"):
        cls.ref_plaintext = ref_plaintext
        prepare_database(ref_plaintext)

    def test_auth_errors(self):
        return
        client = TestClient(app)

        alice = User(config_file=Path("tests/alice.topsecret"))

        r = client.get("/item/")
        assert r.status_code == 401
        assert r.json()["detail"] == "No challenge provided with the request"

        # ==============================================================================

        r = client.get("/item/", headers={"Challenge": "false"})
        assert r.status_code == 401
        assert (
            "Invalid format for challenge. Shall be <user_id>:<b64_hash>:<b64_sign>"
            in r.json()["detail"]
        )

        # ==============================================================================

        challenge_str = alice.build_challenge()
        time.sleep(challenge_auth.challenge_timeout + 1)
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 401
        assert "Challenge expired" in r.json()["detail"]

        # ==============================================================================

        challenge_str = alice.build_challenge()
        # Creation of an invalid challenge (timestamp)
        elem = challenge_str.split(":")
        elem[0] = "1245636"
        challenge_str = ":".join(elem)
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 401
        assert "The user making the challenge could not be found" in r.json()["detail"]

        # ==============================================================================

        challenge_str = alice.build_challenge()
        # Creation of an invalid challenge (timestamp)
        elem = challenge_str.split(":")
        if elem[1][0] == "a":
            b64_hash = "b" + elem[1][1:]
        else:
            b64_hash = "a" + elem[1][1:]
        elem[1] = b64_hash
        challenge_str = ":".join(elem)
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 401
        assert "Impossible to get timestamp from challenge" in r.json()["detail"]

        # ==============================================================================

        challenge_str = alice.build_challenge()
        # Creation of an invalid challenge (signature)
        elem = challenge_str.split(":")
        if elem[2][0] == "a":
            b64_sign = "b" + elem[2][1:]
        else:
            b64_sign = "a" + elem[2][1:]
        elem[2] = b64_sign
        challenge_str = ":".join(elem)
        r = client.get("/item/", headers={"Challenge": challenge_str})
        assert r.status_code == 401
        assert "Invalid challenge signature" in r.json()["detail"]


if __name__ == "__main__":
    TestAuthentication.setUpClass()
    a = TestAuthentication()
    a.test_auth_errors()
