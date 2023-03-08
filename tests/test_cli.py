from typer.testing import CliRunner

from network.backend.main import tapp


runner = CliRunner()


def test_app():
    result = runner.invoke(tapp, ["--port", 3035, "--test"])
    assert result.exit_code == 0


if __name__ == "__main__":
    test_app()
