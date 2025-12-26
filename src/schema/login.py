"""
Fastkey API

Pydantic Models for Login
"""

from json import loads
from typing import Any

from pydantic import BaseModel, Field, field_validator


class LoginCredentialResponse(BaseModel):
    """
    Login Credential Response
    """

    clientDataJSON: str
    authenticatorData: str
    signature: str
    userHandle: str


class LoginCredential(BaseModel):
    """
    Login Credentials
    """

    id: str
    rawId: str
    response: LoginCredentialResponse
    authenticatorAttachment: str
    clientExtensionResults: dict = Field(examples=[{}])
    type: str

    @field_validator("response", mode="before")
    @classmethod
    def transform(cls, raw: Any) -> LoginCredentialResponse:
        """
        Transforms response data into a LoginCredentialResponse instead of
        a string or dictionary, which is likely from Javascript input.
        """
        if isinstance(raw, str):
            return LoginCredentialResponse(**loads(raw))
        if isinstance(raw, dict):
            return LoginCredentialResponse(**raw)
        raise ValueError("response value must be of type str or dict")


class LoginRequest(BaseModel):
    """
    Login Request Model

    Arguments:
        username: string of a username
        credential: LoginCredentialModel
    """

    username: str
    credential: LoginCredential

    @field_validator("credential", mode="before")
    @classmethod
    def transform(cls, raw: Any) -> LoginCredential:
        """
        Transforms response data into a LoginCredential model instead of
        a string or dictionary, which is likely from Javascript input.
        """
        if isinstance(raw, str):
            return LoginCredential(**loads(raw))
        if isinstance(raw, dict):
            return LoginCredential(**raw)
        raise ValueError("credential value must be of type str or dict")
