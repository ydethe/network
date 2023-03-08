from typing import List
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session

from . import schemas
from . import crud
from .models import engine
from .auth_depend import challenge_auth
from .Proxy import Proxy


def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()


router = APIRouter(prefix="/pre", tags=["pre"])


@router.post(
    "/",
    response_model=schemas.PersonDataModel,
    description="Creates one person data for user",
)
def post_reencrypted_data(
    request: Request,
    item: schemas.PersonDataModel = None,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    item.user_id = user_id

    return crud.create_person_data(db=db, item=item)
