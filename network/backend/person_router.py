from typing import List
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session

from . import schemas
from . import crud
from .models import engine
from .auth_depend import challenge_auth


def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()


router = APIRouter(prefix="/person", tags=["person"])


@router.get(
    "/{person_id}",
    response_model=schemas.PersonDataModel,
    description="Retrive one person data for user",
)
def read_person_data(
    request: Request,
    person_id: int = Path(description="ID of the person to retrieve"),
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    db_data = crud.get_person_data(db, user_id, person_id)
    if db_data is None:
        raise HTTPException(status_code=404, detail="Person data not found")
    return db_data


@router.get(
    "/",
    response_model=List[int],
    description="Retrive the list of person data for user",
)
def list_persons(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    db_data = crud.list_persons(db, user_id)
    if db_data is None:
        raise HTTPException(status_code=404, detail="Person data not found")
    return db_data


@router.post(
    "/",
    response_model=schemas.PersonDataModel,
    description="Creates one person data for user",
)
def create_person_data(
    request: Request,
    item: schemas.PersonDataModel = None,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    item.user_id = user_id

    return crud.create_person_data(db=db, item=item)
