from typing import List
from starlette.responses import JSONResponse
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session

from . import schemas
from . import crud
from .models import engine
from .auth_depend import ChallengeMiddleware


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
):
    response = ChallengeMiddleware.analyse_header(request.headers)
    if "error" in response.keys():
        response = JSONResponse(response)
        return response

    user_id = response["user_id"]

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
):
    response = ChallengeMiddleware.analyse_header(request.headers)
    if "error" in response.keys():
        response = JSONResponse(response)
        return response

    user_id = response["user_id"]

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
):
    response = ChallengeMiddleware.analyse_header(request.headers)
    if "error" in response.keys():
        response = JSONResponse(response)
        return response

    item.user_id = response["user_id"]

    return crud.create_person_data(db=db, item=item)
