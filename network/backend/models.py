from base64 import b64decode
from datetime import datetime, timedelta
import os
import logging

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    PrimaryKeyConstraint,
    DateTime,
    create_engine,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from umbral import PublicKey, Signature
from umbral.hashing import Hash


logger = logging.getLogger(f"{__package__}_logger")

Base = declarative_base()

db_uri = os.environ.get("DATABASE_URI", "sqlite:///tests/test_data.db")
logger.info(f"Using database {db_uri}")

engine = create_engine(db_uri, echo=False, future=True)
con = sessionmaker(engine)


class DbUser(Base):

    __tablename__ = "users"

    #: Unique identifier of the session
    id = Column(Integer, primary_key=True, nullable=False)

    public_key = Column(String, nullable=False)

    verifying_key = Column(String, nullable=False)

    time_created = Column(DateTime(timezone=True), server_default=func.now())

    time_updated = Column(DateTime(timezone=True), onupdate=func.now())

    #: List of the related records in person_data table
    person_data = relationship("PersonData", back_populates="user")

    def decodeKeys(self):
        pkey_bytes = b64decode(self.public_key.encode(encoding="ascii"))
        pkey = PublicKey.from_bytes(pkey_bytes)

        vkey_bytes = b64decode(self.verifying_key.encode(encoding="ascii"))
        vkey = PublicKey.from_bytes(vkey_bytes)

        return pkey, vkey

    def check_challenge(self, b64_hash: str, b64_sign: str) -> bool:
        pkey, vkey = self.decodeKeys()

        bdt = b64decode(b64_hash.encode(encoding="ascii"))
        dt = datetime.fromisoformat(bdt.decode(encoding="ascii"))
        t_diff = datetime.now() - dt
        if t_diff > timedelta(seconds=5):
            return False

        hash = Hash()
        hash.update(bdt)

        sign_bytes = b64decode(b64_sign.encode(encoding="ascii"))
        signature = Signature.from_bytes(sign_bytes)

        return signature.verify_digest(vkey, hash)


class PersonData(Base):

    __tablename__ = "person_data"

    #: Unique identifier of the session
    id = Column(Integer, nullable=False, primary_key=True)

    #: Session id the observation belongs to
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    #: Session instance the observation belongs to
    user = relationship("DbUser", back_populates="person_data")

    encrypted_data = Column(String, nullable=False)
