from typing import List

from sqlalchemy.orm import Session

from . import models
from . import schemas


def list_persons(db: Session, user_id: int) -> List[int]:
    lores = db.query(models.PersonData).filter(models.PersonData.user_id == user_id).all()
    res = [ores.id for ores in lores]
    return res


def get_person_data(db: Session, user_id: int, person_id: int) -> List[schemas.PersonDataModel]:
    ores = (
        db.query(models.PersonData)
        .filter(models.PersonData.user_id == user_id)
        .filter(models.PersonData.id == person_id)
        .first()
    )
    res = schemas.PersonDataModel.fromORM(ores)
    return res


def create_person_data(
    db: Session,
    item: schemas.PersonDataModel,
):
    db_item = models.PersonData(**item.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return schemas.PersonDataModel.fromORM(db_item)


def create_user(db: Session, user: schemas.UserModel):
    db_user = models.DbUser(public_key=user.public_key, verifying_key=user.verifying_key)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return schemas.UserModel.fromORM(db_user)
