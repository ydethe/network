from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import schemas
from . import crud
from .models import get_db


router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "/",
    response_model=schemas.UserModel,
    description="Creates a user",
)
def create_user(
    user: schemas.UserModel,
    db: Session = Depends(get_db),
):
    return crud.create_user(db=db, user=user)
