from pathlib import Path
import unittest

import uvicorn
import requests

from network.backend.main import Server
from network.frontend.User import User


class TestFrontend(unittest.TestCase):
    def admin_create_user(self, server_url: str, user: User):
        admin = User(server_url=server_url, config_file=Path("tests/admin.topsecret"))
        challenge_str = admin.build_challenge()
        r = requests.post(
            f"{server_url}/users/", json=user.to_json(), headers={"Challenge": challenge_str}
        )
        if r.status_code != 200:
            raise AssertionError(r.json()["detail"])

        id = r.json()["id"]

        return id

    def test_frontend(
        self,
        host: str = "127.0.0.1",
        port: int = 3035,
        ref_plaintext: str = "Président de la République Française",
    ):
        server_url = f"http://{host}:{port}"

        config = uvicorn.Config(
            "network.backend.main:app",
            host=host,
            port=port,
            log_level="info",
            workers=1,
            reload=False,
        )
        server = Server(config=config)

        id_file = Path("tests/eve.topsecret")

        with server.run_in_thread():
            # User creation
            eve = User(server_url=server_url)
            eve.writeConfigurationFile(id_file)

            # Admin validates user sign up
            eve.id = self.admin_create_user(server_url=server_url, user=eve)
            eve.writeConfigurationFile(id_file)

            # User reloading through the .topsecret file
            eve = User(server_url=server_url, config_file=id_file)

            test_id = eve.saveItemInDatabase(ref_plaintext.encode(encoding="utf-8"))

            l_id = eve.loadItemIdList()
            assert test_id in l_id

            item_id = l_id[0]
            plaintext = eve.loadItemFromDatabase(item_id)

            assert ref_plaintext == plaintext.decode(encoding="utf-8")

            eve.deleteItemFromDatabase(item_id)
            l_id = eve.loadItemIdList()
            assert not item_id in l_id


if __name__ == "__main__":
    a = TestFrontend()
    a.test_frontend()
