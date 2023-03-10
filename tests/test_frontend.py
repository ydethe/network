from pathlib import Path
import unittest

import uvicorn

from network.backend.main import Server
from network.frontend.User import User


class TestFrontend(unittest.TestCase):
    def test_frontend(
        self,
        host: str = "127.0.0.1",
        port: int = 3035,
        ref_plaintext: str = "Président de la République Française",
    ):
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
            eve = User(server_url=f"http://{host}:{port}")
            eve.writeConfigurationFile(id_file)

            # User reloading through the .topsecret file
            eve = User(server_url=f"http://{host}:{port}", config_file=id_file)

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
