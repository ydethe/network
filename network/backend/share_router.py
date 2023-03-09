from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import schemas
from . import crud
from .models import engine, con, DbUser, Item
from .auth_depend import challenge_auth


def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()


router = APIRouter(prefix="/share", tags=["pre"])


@router.post(
    "/{item_id}/{recipient_id}",
    response_model=schemas.ItemModel,
    description="Creates one item data for user",
)
def post_reencrypted_data(
    request: Request,
    item_id: int,
    recipient_id: int,
    kfrag: schemas.KfragModel,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    with con() as session:
        db_item = session.query(Item).filter(Item.id == item_id).first()
        db_sender: DbUser = session.query(DbUser).filter(DbUser.id == user_id).first()  # type: ignore
        db_recipient: DbUser = session.query(DbUser).filter(DbUser.id == recipient_id).first()  # type: ignore

    if db_item is None:
        raise HTTPException(status_code=404, detail=f"Person data {item_id} not found")

    if db_recipient is None:
        raise HTTPException(status_code=404, detail=f"Recipient user {recipient_id} not found")

    sender = schemas.UserModel.fromORM(db_sender)
    recipient = schemas.UserModel.fromORM(db_recipient)

    return crud.post_shared_item(
        db=db,
        sender=sender,
        recipient=recipient,
        db_kfrag=kfrag.kfrag,
        encrypted_data=db_item.encrypted_data,
    )
