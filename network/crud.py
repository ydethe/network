from typing import List

from sqlalchemy.orm import Session

from . import models
from . import schemas


def get_person_data(db: Session, user_id: int, person_id: int) -> schemas.PersonDataModel:
    ores: models.PersonData = (
        db.query(models.PersonData)
        .filter(models.PersonData.user_id == user_id)
        .filter(models.PersonData.person_id == person_id)
        .first()
    )
    res = schemas.PersonDataModel.fromORM(ores)
    return res


def post_person_data(
    db: Session,
    item: schemas.PersonDataModel,
    user_id: int,
    person_id: int,
):
    db_item = models.PersonData(**item.dict(), user_id=user_id, person_id=person_id)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item
