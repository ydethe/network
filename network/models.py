from base64 import b64encode, b64decode
from pathlib import Path

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    LargeBinary,
    DateTime,
    create_engine,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from umbral import SecretKey


Base = declarative_base()

engine = create_engine("sqlite:///tests/test_data.db", echo=False, future=True)
con = sessionmaker(engine)


class DbUser(Base):

    __tablename__ = "users"

    #: Unique identifier of the session
    id = Column(Integer, primary_key=True, nullable=False)

    time_created = Column(DateTime(timezone=True), server_default=func.now())

    time_updated = Column(DateTime(timezone=True), onupdate=func.now())

    #: List of the related records in person_data table
    person_data = relationship("PersonData", back_populates="user")


class PersonData(Base):

    __tablename__ = "person_data"

    #: Unique identifier of the session
    id = Column(Integer, primary_key=True, nullable=False)

    #: Session id the observation belongs to
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    #: Session instance the observation belongs to
    user = relationship("DbUser", back_populates="person_data")

    person_id = Column(Integer, nullable=False)

    data_type = Column(String(32), nullable=False)

    encrypted_data = Column(String, nullable=False)

    UniqueConstraint(
        user_id,
        person_id,
        data_type,
        name="uc_person_data",
    )
