import os
import logging

import uvicorn
from starlette.middleware import Middleware
from fastapi import FastAPI
import typer

from .authentication_middleware import ChallengeMiddleware
from .routers import person_data


tapp = typer.Typer()

app = FastAPI(
    root_path=os.environ.get("ROOT_PATH", ""),
    title="Network API",
    description="API pour accéder à l'annuaire des contacts",
    version="0.1.0",
    middleware=[Middleware(ChallengeMiddleware)],
)

app.include_router(person_data.router)


@tapp.command()
def run_server(
    reload: bool = typer.Option(False, help="Use auto reload in case of code modification"),
    port: int = typer.Option(3034, help="Port on which the server listens"),
):
    nb_workers = int(os.environ.get("NB_WORKERS", "1"))
    logger = logging.getLogger(f"{__package__}_logger")
    logger.info(
        f"""Running app with arguments (root_path='{os.environ.get("ROOT_PATH", "")}', workers={nb_workers}, reload={reload})"""
    )
    uvicorn.run(
        "network.main:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
        workers=nb_workers,
        reload=reload,
    )


def main():
    tapp()


if __name__ == "__main__":
    main()
