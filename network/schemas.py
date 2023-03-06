from pydantic import BaseModel

from . import models


class PersonDataModel(BaseModel):
    id: int
    user_id: int
    person_id: int
    data_type: str
    encrypted_data: str

    @classmethod
    def fromORM(cls, obj: models.PersonData):
        if obj is None:
            return None
        res = cls(
            id=obj.id,
            user_id=obj.user_id,
            person_id=obj.person_id,
            data_type=obj.data_type,
            encrypted_data=obj.encrypted_data,
        )
        return res
