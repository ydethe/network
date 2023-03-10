from pathlib import Path
import json

import requests

from .User import User


class Admin(User):
    """Create an admin user.

    Args:
        server_url: URL of the server
        config_file: File to read to instanciate the user

    """

    def createUser(self, public_file: Path, admin: bool = False):
        """Create a new user from its public file

        Args:
            public_file: Public file created with `network.frontend.User.to_public_file`
            admin: Flag to promote the user as admin

        Returns:
            The id of the new user

        """
        with open(public_file, "r") as f:
            user_data = json.load(f)
        user_data["admin"] = admin
        challenge_str = self.build_challenge()
        r = requests.post(
            f"{self.server_url}/users/", json=user_data, headers={"Challenge": challenge_str}
        )
        if r.status_code != 200:
            raise AssertionError(r.json()["detail"])

        user_id = r.json()["id"]

        return user_id
