"""
Fastkey API

Challenges Models for type verification
"""

from pydantic import BaseModel, Field
from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)


class RegisterChallenge(BaseModel, PublicKeyCredentialCreationOptions):
    """Registration Options.

    Attributes:
        `rp`: Information about the Relying Party
        `user`: Information about the user
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent
                     replay attacks
        `pub_key_cred_params`: Cryptographic algorithms supported by the Relying Party when
                               verifying signatures
        (optional) `timeout`: How long the client/browser should give the user to
                              interact with an authenticator
        (optional) `exclude_credentials`: A list of credentials associated with
                                          the user to prevent them from re-enrolling
                                          one of them
        (optional) `authenticator_selection`: Additional qualities about the authenticators
                                              the user can use to complete registration
        (optional) `hints`: Suggestions to the browser about the type of authenticator the
                            user should try and register. Multiple values should be ordered
                            by decreasing preference
        (optional) `attestation`: The Relying Party's desire for a declaration of an
                                  authenticator's provenance via attestation statement

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
    """


class LoginChallenge(BaseModel, PublicKeyCredentialRequestOptions):
    """Authentication Options.

    Attributes:
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps
                     prevent replay attacks
        (optional) `timeout`: How long the client/browser should give the user to interact
                              with an authenticator
        (optional) `rp_id`: The unique, constant identifier assigned to the Relying On Party
        (optional) `allow_credentials`: A list of credentials associated with the user that
                                        they can use to complete the authentication
        (optional) `user_verification`: How the authenticator should be capable of determining
                                        user identity

    https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    """


class ChallengeAccepted(BaseModel):
    """
    Challenge Accepted Return Model
    """

    message: str = Field(examples=["Challenge Accepted."])
