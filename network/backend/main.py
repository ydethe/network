import os
import logging
import contextlib
import time
import threading
from pathlib import Path

from sqlalchemy import create_engine
import uvicorn
from fastapi import FastAPI
import typer

from . import item_router, user_router, share_router
from ..frontend.Admin import Admin
from ..frontend.User import User
from . import models


tapp = typer.Typer()

app = FastAPI(
    root_path=os.environ.get("ROOT_PATH", ""),
    title="Network API",
    description="API pour accéder à l'annuaire des contacts",
    version="0.1.0",
)

app.include_router(item_router.router)
app.include_router(user_router.router)
app.include_router(share_router.router)


class Server(uvicorn.Server):
    def __init__(self, config: uvicorn.Config) -> None:
        super().__init__(config)

    def install_signal_handlers(self):
        pass

    @contextlib.contextmanager
    def run_in_thread(self):
        thread = threading.Thread(target=self.run)
        thread.start()
        try:
            while not self.started:
                time.sleep(1e-3)
            yield
        finally:
            self.should_exit = True
            thread.join()

@tapp.command()
def create(key_path:Path=typer.Option(None,help="Where to save the private key"),admin:bool=typer.Option(False,help="Administrator flag")):
    "Crate a new user"
    db_uri = os.environ.get("DATABASE_URI", "sqlite:///tests/test_data.db")

    logger = logging.getLogger("network_logger")
    logger.info(f"Using {db_uri}")

    user = User()
    data = user.to_json()
    db_admin = models.DbUser(
        admin=admin, public_key=data["public_key"], verifying_key=data["verifying_key"]
    )
    with models.con() as session:
        session.add(db_admin)
        session.commit()
        session.refresh(db_admin)
        user.id = db_admin.id
    
    if key_path is not None:
        user.to_topsecret_file(key_path)
        logger.info(f"Key generated {key_path}")

@tapp.command()
def run_server(
    reload: bool = typer.Option(False, help="Use auto reload in case of code modification"),
    port: int = typer.Option(3034, help="Port on which the server listens"),
    workers: int = typer.Option(1, help="Number of workers"),
    test: bool = typer.Option(False, help="Flag to run the server for only one second"),
):
    "Run server"
    db_uri = os.environ.get("DATABASE_URI", "sqlite:///tests/test_data.db")

    logger = logging.getLogger("network_logger")
    logger.info(
        f"""Running app with arguments (root_path='{os.environ.get("ROOT_PATH", "")}', workers={workers}, reload={reload})"""
    )
    logger.info(f"Using {db_uri}")

    engine = create_engine(db_uri, echo=False)
    target_metadata = models.Base.metadata
    target_metadata.create_all(engine)

    admin_key_path=Path("admin.topsecret")
    if not admin_key_path.exists():
        create(admin=True, key_path=admin_key_path)

    config = uvicorn.Config(
        "network.backend.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        workers=workers,
        reload=reload,
    )
    server = Server(config=config)

    server.should_exit = test

    with server.run_in_thread():
        while not server.should_exit:
            pass
