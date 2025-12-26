"""
Fastkey API

Pydantic Models for User Registration
"""

from json import loads
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class RegisterCredentialResponse(BaseModel):
    """
    Registration Credential Response Model
    """

    clientDataJSON: str
    authenticatorData: str
    transports: list[Optional[str]]
    publicKey: str
    publicKeyAlgorithm: int
    attestationObject: str


class RegisterCredential(BaseModel):
    """
    Registration Credentials
    """

    id: str
    rawId: str
    response: RegisterCredentialResponse
    authenticatorAttachment: str
    clientExtensionResults: dict
    type: str

    @field_validator("response", mode="before")
    @classmethod
    def transform(cls, raw: Any) -> RegisterCredentialResponse:
        """
        Transforms response data into a RegisterCredentialResponse instead of
        a string or dictionary, which is likely from Javascript input.
        """
        if isinstance(raw, str):
            return RegisterCredentialResponse(**loads(raw))
        if isinstance(raw, dict):
            return RegisterCredentialResponse(**raw)
        raise ValueError("response value must be of type str or dict")


class RegisterRequest(BaseModel):
    """
    Register User request

    Arguments:
        username: Unique string username
        credential: RegisterCredential Model
    """

    username: str = Field(examples=["anybody"])
    credential: RegisterCredential

    @field_validator("credential", mode="before")
    @classmethod
    def transform(cls, raw: Any) -> RegisterCredential:
        """
        Transforms response data into a RegisterCredential model instead of
        a string or dictionary, which is likely from Javascript input.
        """
        if isinstance(raw, str):
            return RegisterCredential(**loads(raw))
        if isinstance(raw, dict):
            return RegisterCredential(**raw)
        raise ValueError("credential value must be of type str or dict")
