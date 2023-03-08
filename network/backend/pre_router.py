from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import schemas
from . import crud
from .models import engine, con, DbUser, PersonData
from .auth_depend import challenge_auth


def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()


router = APIRouter(prefix="/pre", tags=["pre"])


@router.post(
    "/{person_id}/{recipient_id}",
    response_model=schemas.PersonDataModel,
    description="Creates one person data for user",
)
def post_reencrypted_data(
    request: Request,
    person_id: int,
    recipient_id: int,
    kfrag: schemas.KfragModel,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    with con() as session:
        db_item = session.query(PersonData).filter(PersonData.id == person_id).first()
        db_sender: DbUser = session.query(DbUser).filter(DbUser.id == user_id).first()  # type: ignore
        db_recipient: DbUser = session.query(DbUser).filter(DbUser.id == recipient_id).first()  # type: ignore

    sender = schemas.UserModel.fromORM(db_sender)
    recipient = schemas.UserModel.fromORM(db_recipient)

    return crud.post_shared_data(
        db=db,
        sender=sender,
        recipient=recipient,
        db_kfrag=kfrag.kfrag,
        encrypted_data=db_item.encrypted_data,
    )
