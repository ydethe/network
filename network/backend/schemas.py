from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from . import models


class PersonDataModel(BaseModel):
    id: Optional[int]
    user_id: Optional[int]
    encrypted_data: str

    @classmethod
    def fromORM(cls, obj: models.PersonData):
        if obj is None:
            return None
        res = cls(
            id=obj.id,
            user_id=obj.user_id,
            encrypted_data=obj.encrypted_data,
        )
        return res


class UserModel(BaseModel):
    id: Optional[int]
    public_key: str
    verifying_key: str
    time_created: Optional[datetime]
    time_updated: Optional[datetime]

    @classmethod
    def fromORM(cls, obj: models.DbUser):
        if obj is None:
            return None
        res = cls(
            id=obj.id,
            public_key=obj.public_key,
            verifying_key=obj.verifying_key,
            time_created=obj.time_created,
            time_updated=obj.time_updated,
        )
        return res
