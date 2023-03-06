from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    LargeBinary,
    DateTime,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship


Base = declarative_base()


class User(Base):

    __tablename__ = "users"

    #: Unique identifier of the session
    id = Column(Integer, primary_key=True, nullable=False)

    private_key = Column(LargeBinary, nullable=False)

    signing_key = Column(LargeBinary, nullable=False)

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
    user = relationship("User", back_populates="person_data")

    person_id = Column(Integer, nullable=False)

    data_type = Column(String(32), nullable=False)

    crypted_data = Column(LargeBinary, nullable=False)

    UniqueConstraint(
        user_id,
        person_id,
        data_type,
        name="uc_person_data",
    )
