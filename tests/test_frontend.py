from pathlib import Path

from network.frontend.User import User


def ntest_frontend():
    id_file = Path("~/.network.topsecret")

    me = User(server_url="https://network.johncloud.fr/v1", config_file=id_file)
    me.writeConfigurationFile(id_file)

    print(me.saveItemInDatabase(b"Je suis un poney"))
    l_id = me.loadItemIdList()
    print(l_id)
    print(me.loadItemFromDatabase(l_id[0]))


if __name__ == "__main__":
    ntest_frontend()
