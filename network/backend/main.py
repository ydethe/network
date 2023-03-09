import os
import logging
import contextlib
import time
import threading

import uvicorn
from fastapi import FastAPI
import typer

from . import item_router, user_router, pre_router


tapp = typer.Typer()

app = FastAPI(
    root_path=os.environ.get("ROOT_PATH", ""),
    title="Network API",
    description="API pour accéder à l'annuaire des contacts",
    version="0.1.0",
)

app.include_router(item_router.router)
app.include_router(user_router.router)
app.include_router(pre_router.router)


class Server(uvicorn.Server):
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
def run_server(
    reload: bool = typer.Option(False, help="Use auto reload in case of code modification"),
    port: int = typer.Option(3034, help="Port on which the server listens"),
    workers: int = typer.Option(1, help="Number of workers"),
    test: bool = typer.Option(False, help="Flag to run the server for only one second"),
):
    logger = logging.getLogger(f"{__package__}_logger")
    logger.info(
        f"""Running app with arguments (root_path='{os.environ.get("ROOT_PATH", "")}', workers={workers}, reload={reload})"""
    )
    config = uvicorn.Config(
        "network.backend.main:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
        workers=workers,
        reload=reload,
    )
    server = Server(config=config)

    with server.run_in_thread():
        while not test:
            pass
