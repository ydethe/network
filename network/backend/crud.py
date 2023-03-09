from typing import List, Union

from sqlalchemy.orm import Session

from network.backend.Proxy import Proxy

from . import models
from .. import schemas
from ..transcoding import cfrag_to_json, db_bytes_to_encrypted, db_bytes_to_kfrag


def list_items(db: Session, user_id: int) -> List[int]:
    lores = db.query(models.Item).filter(models.Item.user_id == user_id).all()
    res = [ores.id for ores in lores]
    return res


def get_item(db: Session, user_id: int, item_id: int) -> Union[schemas.ItemModel, None]:
    ores: models.Item = (
        db.query(models.Item)
        .filter(models.Item.user_id == user_id)
        .filter(models.Item.id == item_id)
        .first()
    )  # type: ignore
    if ores is None:
        return None
    res = schemas.ItemModel.fromORM(ores)
    return res


def delete_item(db: Session, user_id: int, item_id: int) -> bool:
    ores: models.Item = (
        db.query(models.Item)
        .filter(models.Item.user_id == user_id)
        .filter(models.Item.id == item_id)
        .first()
    )  # type: ignore
    if ores is None:
        return False
    db.delete(ores)
    db.commit()
    return True


def create_item(
    db: Session,
    item: schemas.ItemModel,
) -> Union[schemas.ItemModel, None]:
    db_item = models.Item(**item.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return schemas.ItemModel.fromORM(db_item)


def create_user(db: Session, user: schemas.UserModel) -> Union[schemas.UserModel, None]:
    db_user = models.DbUser(public_key=user.public_key, verifying_key=user.verifying_key)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return schemas.UserModel.fromORM(db_user)


def post_shared_item(
    db: Session,
    sender: schemas.UserModel,
    recipient: schemas.UserModel,
    db_kfrag: str,
    encrypted_data: str,
) -> Union[schemas.ItemModel, None]:
    capsule, ciphertext = db_bytes_to_encrypted(encrypted_data)
    kfrag = db_bytes_to_kfrag(db_kfrag)
    u = Proxy()
    cfrag = u.reencrypt(capsule, kfrag)
    db_cfrag = cfrag_to_json(cfrag)
    db_item = models.Item(
        user_id=recipient.id,
        encrypted_data=encrypted_data,
        cfrag=db_cfrag["cfrag"],
        sender_pkey=sender.public_key,
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return schemas.ItemModel.fromORM(db_item)
