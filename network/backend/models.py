from base64 import b64decode
from datetime import datetime, timedelta
import os

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    Boolean,
    String,
    DateTime,
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base, Session, relationship, sessionmaker
from umbral import Signature
from umbral.hashing import Hash

from .. import logger
from ..transcoding import challenge_to_datetime, decodeKey


Base = declarative_base()


def get_connection():
    db_uri = os.environ.get("DATABASE_URI", "sqlite+aiosqlite:///tests/test_data.db")

    engine = create_async_engine(db_uri, echo=False, future=True)
    con = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    logger.info(f"Using database {db_uri}")

    return con


def get_db():
    con = get_connection()
    engine = con.kw["bind"]
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()


class DbUser(Base):

    __tablename__ = "users"

    #: Unique identifier of the session
    id = Column(Integer, primary_key=True, nullable=False)

    admin = Column(Boolean, nullable=False, default=False)

    public_key = Column(String, nullable=False)

    verifying_key = Column(String, nullable=False)

    time_last_challenge = Column(DateTime(timezone=True), nullable=True)

    time_created = Column(DateTime(timezone=True), server_default=func.now())

    time_updated = Column(DateTime(timezone=True), onupdate=func.now())

    #: List of the related records in items table
    items = relationship("Item", back_populates="user")

    async def check_challenge(
        self, session: Session, b64_hash: str, b64_sign: str, timeout: float
    ) -> dict:
        """Check if the proposed challenge is valid.
        The challenge consists in b64_hash and b64_sign.
        The conditions to succeed in checking the challenge are :

        * the signature matches the user's verifying key
        * a datetime object can be retrieved from b64_hash
        * this datetime object is different from the last challenge datetime (stored in database)
        * this datetime object is at most timeout seconds before now

        The returned dictionary has the following keys:

        * status: 200 in case of success, 401 otherwise
        * message: A message that explains the reason of the failure

        Args:
            session: A SQLAlchemy session to update the last challenge datetime
            b64_hash: The challenge hash
            b64_sign: The challenge signature
            timeout: The timeout to invalidate old challenges

        Returns:
            A dictionary that gives the status of the check

        """
        vkey = decodeKey(self.verifying_key)

        challenge_data = challenge_to_datetime(b64_hash)
        if challenge_data["status"] != 200:
            return challenge_data

        if (
            self.time_last_challenge is not None
            and challenge_data["datetime"] == self.time_last_challenge
        ):
            response = {
                "status": 401,
                "message": "Trying to reuse a challenge",
            }
            return response

        t_diff = datetime.now() - challenge_data["datetime"]
        if t_diff > timedelta(seconds=timeout):
            response = {
                "status": 401,
                "message": f"Challenge expired ({t_diff.total_seconds()} s elapsed)",
            }
            return response

        hash = Hash()
        hash.update(challenge_data["iso"].encode(encoding="ascii"))

        sign_bytes = b64decode(b64_sign.encode(encoding="ascii"))
        signature = Signature.from_bytes(sign_bytes)

        if signature.verify_digest(vkey, hash):
            self.time_last_challenge = challenge_data["datetime"]
            await session.commit()
            response = {
                "status": 200,
                "message": "OK",
            }
            return response
        else:
            response = {
                "status": 401,
                "message": "Invalid challenge signature",
            }
            return response


class Item(Base):

    __tablename__ = "items"

    #: Unique identifier of the session
    id = Column(Integer, nullable=False, primary_key=True)

    #: Session id the observation belongs to
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    #: Session instance the observation belongs to
    user = relationship("DbUser", back_populates="items")

    encrypted_data = Column(String, nullable=False)

    cfrag = Column(String, nullable=True)

    sender_pkey = Column(String, nullable=True)
