from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from umbral import PublicKey, VerifiedCapsuleFrag, Capsule

from .transcoding import db_bytes_to_cfrag, db_bytes_to_encrypted, decodeKey
from .backend import models


@dataclass
class UmbralMessage:
    #: The encapsulated symmetric key returnd by the encrypt method
    capsule: Capsule
    #: The ciphertext returnd by the encrypt method
    ciphertext: bytes
    #: ID of the data in the database
    id: Optional[int] = None
    #: ID of the user that owns the data
    user_id: Optional[int] = None
    #: Capsule frag used to decrypt the data. Used only if the data has been shared by another user
    cfrag: Optional[VerifiedCapsuleFrag] = None
    #: Public key of the user who shared the data
    sender_pkey: Optional[PublicKey] = None


class KfragModel(BaseModel):
    kfrag: str


class CfragModel(BaseModel):
    cfrag: str


class ItemModel(BaseModel):
    id: Optional[int] = None
    user_id: Optional[int] = None
    encrypted_data: str
    cfrag: Optional[str] = None
    sender_pkey: Optional[str] = None

    @classmethod
    def fromORM(cls, obj: models.Item) -> "ItemModel":
        """Build a ItemModel from a db record

        Args:
            obj: Database record

        Returns:
            A ItemModel instance

        """
        res = cls(
            id=obj.id,
            user_id=obj.user_id,
            encrypted_data=obj.encrypted_data,
            cfrag=obj.cfrag,
            sender_pkey=obj.sender_pkey,
        )
        return res

    def toUmbral(self) -> UmbralMessage:
        """Convert ItemModel, which is the database representation,
        to a class whose attributes are umbral objects

        Returns:
            A class whose attributes are umbral objects

        """
        capsule, ciphertext = db_bytes_to_encrypted(self.encrypted_data)
        if self.cfrag is None:
            cfrag = None
        else:
            cfrag = db_bytes_to_cfrag(self.cfrag)

        if self.sender_pkey is None:
            sender_pkey = None
        else:
            sender_pkey = decodeKey(self.sender_pkey)

        res = UmbralMessage(
            id=self.id,
            user_id=self.user_id,
            capsule=capsule,
            ciphertext=ciphertext,
            cfrag=cfrag,
            sender_pkey=sender_pkey,
        )

        return res


class UserModel(BaseModel):
    id: Optional[int] = None
    public_key: str
    verifying_key: str
    time_created: Optional[datetime] = None
    time_updated: Optional[datetime] = None

    @classmethod
    def fromORM(cls, obj: models.DbUser) -> "UserModel":
        """Build a UserModel from a db record

        Args:
            obj: Database record

        Returns:
            A UserModel instance

        """
        res = cls(
            id=obj.id,
            public_key=obj.public_key,
            verifying_key=obj.verifying_key,
            time_created=obj.time_created,
            time_updated=obj.time_updated,
        )
        return res
