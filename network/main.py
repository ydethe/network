import os
import logging

import uvicorn
from fastapi import FastAPI

from .routers import person_data


app = FastAPI(
    root_path=os.environ.get("ROOT_PATH", ""),
    title="Network API",
    description="API pour accéder à l'annuaire des contacts",
    version="0.1.0",
)

app.include_router(person_data.router)


def main(reload: bool = False):
    nb_workers = int(os.environ.get("NB_WORKERS", "1"))
    logger = logging.getLogger(f"{__package__}_logger")
    logger.info(
        f"""Running app with arguments (root_path='{os.environ.get("ROOT_PATH", "")}', workers={nb_workers}, reload={reload})"""
    )
    uvicorn.run(
        "network.main:app",
        host="127.0.0.1",
        port=3032,
        log_level="info",
        workers=nb_workers,
        reload=reload,
    )


if __name__ == "__main__":
    main()
