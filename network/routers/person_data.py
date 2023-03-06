from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session

from .. import schemas
from .. import crud
from ..models import engine


def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()


router = APIRouter(prefix="/person", tags=["person"])


@router.get(
    "/{user_id}/{person_id}",
    response_model=schemas.PersonDataModel,
    description="Retrive one person data for user",
)
def read_person_data(
    user_id: int = Path(description="ID of the user the data belongs to"),
    person_id: int = Path(description="ID of the person to retrieve"),
    db: Session = Depends(get_db),
):
    db_data = crud.get_person_data(db, user_id, person_id)
    if db_data is None:
        raise HTTPException(status_code=404, detail="Person data not found")
    return db_data


@router.post(
    "/{user_id}/{person_id}",
    response_model=schemas.PersonDataModel,
    description="Creates one person data for user",
)
def create_person_data(
    user_id: int = Path(description="ID of the user the data belongs to"),
    person_id: int = Path(description="ID of the person to retrieve"),
    item: schemas.PersonDataModel = None,
    db: Session = Depends(get_db),
):
    return crud.post_person_data(db=db, item=item, user_id=user_id, person_id=person_id)
