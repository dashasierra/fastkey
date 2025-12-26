"""
Transactional database using SQLAlchemy ORM
"""

import logging
import os
from dataclasses import dataclass

from pydantic import BaseModel, field_validator
from sqlalchemy import Column, Integer, LargeBinary, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class UserAlreadyExistsError(Exception):
    """Raised when a user already exists."""


class UserDatabase:
    """
    SQLAlchemy Database with Dictionary like attributes
    """

    # -------------------------
    # Pydantic Validator
    # -------------------------
    class Validator(BaseModel):
        """
        Validates Data Class
        """

        username: str
        credential_id: bytes
        public_key: bytes
        sign_count: int
        rp_id: str

        model_config = {"extra": "forbid"}

        @field_validator("username", "rp_id")
        @classmethod
        def non_empty(cls, v):
            """
            Determines that username and rp_id are not empty
            """
            if not v.strip():
                raise ValueError("Field cannot be empty")
            return v

        @field_validator("sign_count")
        @classmethod
        def non_negative(cls, v):
            """
            Determines that sign_count cannot be less than 0
            """
            if v < 0:
                raise ValueError("sign_count must be >= 0")
            return v

    @dataclass
    class User(Base):
        """
        User Data Class
        """

        __tablename__ = "users"

        username = Column(
            String, unique=True, primary_key=True, index=True, nullable=False
        )
        credential_id = Column(LargeBinary, unique=True, index=True, nullable=False)
        public_key = Column(LargeBinary, unique=True, nullable=False)
        sign_count = Column(Integer, nullable=False)
        rp_id = Column(String, nullable=False)

        def __init__(self, **kwargs):
            validate = UserDatabase.Validator(**kwargs)
            self.username = validate.username
            self.credential_id = validate.credential_id
            self.public_key = validate.public_key
            self.sign_count = validate.sign_count
            self.rp_id = validate.rp_id

    class UserRecord:
        """
        UserRecord Wrapper

        Dict-like view over a single user row.
        Supports:
            users_db["alice"]["sign_count"]
            users_db["alice"]["sign_count"] = 42
        """

        def __init__(self, db: "UserDatabase", username: str):
            self._db = db
            self._username = username

        def __getitem__(self, field: str):
            with self._db.session_local() as session:
                user = session.execute(
                    select(self._db.User).where(
                        self._db.User.username == self._username
                    )
                ).scalar_one_or_none()

                if user is None:
                    raise KeyError(f"User '{self._username}' not found")

                if not hasattr(user, field):
                    raise KeyError(f"Field '{field}' does not exist")

                return getattr(user, field)

        def __setitem__(self, field: str, value):
            allowed_fields = {"credential_id", "public_key", "sign_count", "rp_id"}

            if field not in allowed_fields:
                raise KeyError(f"Field '{field}' cannot be updated")

            with self._db.session_local() as session:
                user = session.execute(
                    select(self._db.User).where(
                        self._db.User.username == self._username
                    )
                ).scalar_one_or_none()

                if user is None:
                    raise KeyError(f"User '{self._username}' not found")

                # Build full data for validation
                data = {
                    "username": user.username,
                    "credential_id": user.credential_id,
                    "public_key": user.public_key,
                    "sign_count": user.sign_count,
                    "rp_id": user.rp_id,
                    field: value,
                }

                # Validate with Pydantic
                model = self._db.Validator(**data)

                # Apply update
                setattr(user, field, getattr(model, field))
                session.commit()

    def __init__(self, database_url=os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")):
        """
        Initialise SQLAlchemy Database Core

        Arguments:
            database_url: SQLAlchemy Engine Creation String
        """
        self.engine = create_engine(database_url)
        self.session_local = sessionmaker(bind=self.engine, expire_on_commit=False)
        Base.metadata.create_all(bind=self.engine)

    def user_exists(self, username: str) -> bool:
        """
        Returns True/False if the given username exists in the database
        """
        with self.session_local() as session:
            stmt = select(self.User).where(self.User.username == username)
            return session.execute(stmt).scalar_one_or_none() is not None

    def __setitem__(self, key: str, value: dict):
        if "username" in value:
            raise KeyError("Username cannot be part of value payload")

        model = self.Validator(username=key, **value)

        with self.session_local() as session:
            try:
                user = self.User(
                    username=model.username,
                    credential_id=model.credential_id,
                    public_key=model.public_key,
                    sign_count=model.sign_count,
                    rp_id=model.rp_id,
                )
                session.add(user)
                session.commit()

            except IntegrityError as err:
                session.rollback()
                raise UserAlreadyExistsError(
                    f"The user '{key}' already exists"
                ) from err

    def __getitem__(self, key: str):
        return self.UserRecord(self, key)


# Instantiate database
users_db = UserDatabase()

logging.info("Running with db_alchemy module")
