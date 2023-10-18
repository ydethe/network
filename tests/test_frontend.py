from pathlib import Path
import unittest

import uvicorn
import requests

from network.backend.main import Server
from network.frontend.Admin import Admin
from network.frontend.User import User


class TestFrontend(unittest.TestCase):
    def admin_create_user(self, server_url: str, public_file: Path):
        import network.backend.models as md

        admin = Admin(server_url=server_url)
        data = admin.to_json()
        db_admin = md.DbUser(
            admin=True, public_key=data["public_key"], verifying_key=data["verifying_key"]
        )
        with md.con() as session:
            session.add(db_admin)
            session.commit()
            session.refresh(db_admin)
            admin.id = db_admin.id

        user_id = admin.createUser(public_file)

        return user_id

    def test_frontend(
        self,
        host: str = "127.0.0.1",
        port: int = 3100,
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
            eve.to_topsecret_file(id_file)
            eve_public = Path("tests/eve.public")
            eve.to_public_file(eve_public)

            # Admin validates user sign up
            eve.id = self.admin_create_user(server_url=server_url, public_file=eve_public)
            eve.to_topsecret_file(id_file)

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
