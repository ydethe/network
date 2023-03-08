from base64 import b64decode, b64encode
from datetime import datetime, timedelta
import os
import logging
from typing import Tuple
import struct

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    DateTime,
    create_engine,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from umbral import PublicKey, Signature, Capsule, VerifiedKeyFrag
from umbral.hashing import Hash

from ..transcoding import decodeKey


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

    last_challenge_dt = Column(String, nullable=True)

    time_created = Column(DateTime(timezone=True), server_default=func.now())

    time_updated = Column(DateTime(timezone=True), onupdate=func.now())

    #: List of the related records in person_data table
    person_data = relationship("PersonData", back_populates="user")

    def check_challenge(self, b64_hash: str, b64_sign: str, timeout: float) -> bool:
        pkey = decodeKey(self.public_key)
        vkey = decodeKey(self.verifying_key)

        bdt = b64decode(b64_hash.encode(encoding="ascii"))
        sdt = bdt.decode(encoding="ascii")
        if not self.last_challenge_dt is None and sdt == self.last_challenge_dt:
            return False

        dt = datetime.fromisoformat(sdt)
        t_diff = datetime.now() - dt
        if t_diff > timedelta(seconds=timeout):
            return False

        hash = Hash()
        hash.update(bdt)

        sign_bytes = b64decode(b64_sign.encode(encoding="ascii"))
        signature = Signature.from_bytes(sign_bytes)

        if signature.verify_digest(vkey, hash):
            self.last_challenge_dt = sdt
            return True
        else:
            return False


class PersonData(Base):

    __tablename__ = "person_data"

    #: Unique identifier of the session
    id = Column(Integer, nullable=False, primary_key=True)

    #: Session id the observation belongs to
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    #: Session instance the observation belongs to
    user = relationship("DbUser", back_populates="person_data")

    encrypted_data = Column(String, nullable=False)

    cfrag = Column(String, nullable=True)

    sender_pkey = Column(String, nullable=True)
