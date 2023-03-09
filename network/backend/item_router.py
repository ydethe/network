from typing import List
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session

from .. import schemas
from . import crud
from .models import get_db
from .auth_depend import challenge_auth


router = APIRouter(prefix="/item", tags=["item"])


@router.get(
    "/{item_id}",
    response_model=schemas.ItemModel,
    description="Retrive one item data for user",
)
def read_item_data(
    request: Request,
    item_id: int = Path(description="ID of the item to retrieve"),
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    db_data = crud.get_item(db, user_id, item_id)
    if db_data is None:
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
    return db_data

@router.delete(
    "/{item_id}",
    description="Delete one item data for user",
)
def delete_item_data(
    request: Request,
    item_id: int = Path(description="ID of the item to retrieve"),
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    ok = crud.delete_item(db, user_id, item_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")


@router.get(
    "/",
    response_model=List[int],
    description="Retrive the list of item data for user",
)
def list_items(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    db_data = crud.list_items(db, user_id)
    return db_data


@router.post(
    "/",
    response_model=schemas.ItemModel,
    description="Creates one item data for user",
)
def create_item(
    request: Request,
    item: schemas.ItemModel = None,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    item.user_id = user_id

    return crud.create_item(db=db, item=item)
