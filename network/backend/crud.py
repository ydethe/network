from typing import List, Union

from sqlalchemy.orm import Session

from network.backend.Proxy import Proxy

from . import models
from .. import schemas
from ..transcoding import db_bytes_to_encrypted, db_bytes_to_kfrag


def list_persons(db: Session, user_id: int) -> List[int]:
    lores = db.query(models.PersonData).filter(models.PersonData.user_id == user_id).all()
    res = [ores.id for ores in lores]
    return res


def get_person_data(
    db: Session, user_id: int, person_id: int
) -> Union[schemas.PersonDataModel, None]:
    ores: models.DbUser = (
        db.query(models.PersonData)
        .filter(models.PersonData.user_id == user_id)
        .filter(models.PersonData.id == person_id)
        .first()
    )  # type: ignore
    res = schemas.PersonDataModel.fromORM(ores)
    return res


def create_person_data(
    db: Session,
    item: schemas.PersonDataModel,
) -> Union[schemas.PersonDataModel, None]:
    db_item = models.PersonData(**item.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return schemas.PersonDataModel.fromORM(db_item)


def create_user(db: Session, user: schemas.UserModel) -> Union[schemas.UserModel, None]:
    db_user = models.DbUser(public_key=user.public_key, verifying_key=user.verifying_key)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return schemas.UserModel.fromORM(db_user)


def post_shared_data(
    db: Session,
    sender: schemas.UserModel,
    recipient: schemas.UserModel,
    db_kfrag: str,
    encrypted_data: str,
) -> Union[schemas.PersonDataModel, None]:
    capsule, ciphertext = db_bytes_to_encrypted(encrypted_data)
    kfrag = db_bytes_to_kfrag(db_kfrag)
    u = Proxy()
    cfrag = u.reencrypt(capsule, kfrag)
    db_cfrag = Proxy.cfrag_to_db_bytes(cfrag)
    db_item = models.PersonData(
        user_id=recipient.id,
        encrypted_data=encrypted_data,
        cfrag=db_cfrag["cfrag"],
        sender_pkey=sender.public_key,
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return schemas.PersonDataModel.fromORM(db_item)
