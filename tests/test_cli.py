from typer.testing import CliRunner

from network.backend.main import tapp


runner = CliRunner()


def test_app():
    runner.invoke(tapp, ["--port", 3035, "--test"])


if __name__ == "__main__":
    test_app()
