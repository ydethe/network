from typing import List

from sqlalchemy.orm import Session

from . import models
from . import schemas


def list_persons(db: Session, user_id: int) -> List[int]:
    lores = (
        db.query(models.PersonData)
        .filter(models.PersonData.user_id == user_id)
        .distinct(models.PersonData.person_id)
        .all()
    )
    ores: models.PersonData
    res = [ores.person_id for ores in lores]
    return res


def get_person_data(db: Session, user_id: int, person_id: int) -> List[schemas.PersonDataModel]:
    lores = (
        db.query(models.PersonData)
        .filter(models.PersonData.user_id == user_id)
        .filter(models.PersonData.person_id == person_id)
        .all()
    )
    res = [schemas.PersonDataModel.fromORM(ores) for ores in lores]
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
