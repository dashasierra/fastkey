"""
Fastkey Auth Router

Contains all functions and endpoints relating
to Passkey authentication.
"""

import base64
import os
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Optional, Union

import starlette.datastructures
from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttachment,
    AuthenticatorAttestationResponse,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    RegistrationCredential,
)

from ..db import challenges_db, users_db
from ..schema.challenge import ChallengeAccepted, LoginChallenge, RegisterChallenge
from ..schema.login import LoginRequest
from ..schema.register import RegisterRequest

router = APIRouter()

# Load Javascript for Serving
try:
    with open(
        os.path.dirname(__file__) + "/js/fastkey.js", "r", encoding="utf-8"
    ) as js_file:
        javascript = js_file.read()  # pylint: disable=consider-using-with
except FileNotFoundError:
    # This should only happen during Git Tests
    javascript = ""
JAVASCRIPT_MODIFIED = False  # This flag indicates no change yet

# Set Hostname to HOSTNAME variable
__hostname = os.getenv("HOSTNAME", None)
__hostname_header = os.getenv("HOST_HEADER", "host")


class Insert(Enum):
    """
    Insert type enumerator
    """

    ORIGIN = "uri"
    RP_ID = "rp_id"


def get_host_name(
    of: Insert = Insert.ORIGIN, headers: starlette.datastructures.Headers = None
) -> str:
    """
    Returns the Host Name for various implementations

    Arguments:
        of: What HostType to return
        headers: Optional headers
    """
    global __hostname  # pylint: disable=global-statement
    if __hostname is None:
        # Hostname was not set yet
        if headers is None:
            # We don't have headers, so we have to assume it's local.
            __hostname = "http://localhost:8000"
        else:
            header_hostname = headers.get(__hostname_header)
            if header_hostname.startswith("localhost") or header_hostname.startswith(
                "127.0.0.1"
            ):
                __hostname = f"http://{header_hostname}"
            else:
                __hostname = f"https://{header_hostname}"
    else:
        pass  # Hostname is already set, nothing to do here
    if of == Insert.RP_ID:
        # The RP_ID should just be the hostname, so we need to remove http(s),
        # ports, and trailing addresses
        return __hostname.split("//", 1)[-1].split(":", 1)[0].split("/", 1)[0]
    # HostType.ORIGIN - Return the entire URL
    return __hostname


def bytes_to_base64url(data: bytes) -> str:
    """
    Convert bytes to base64 urlsafe string without padding.
    """
    pad = "="
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip(pad)


def base64url_to_bytes(data: str) -> bytes:
    """
    Convert base64 urlsafe string to bytes with padding.
    """
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def to_registration_credential(
    credential: Union[BaseModel, dict],
) -> RegistrationCredential:
    """
    Convert credential into a py_webauthn dataclass model.
    """
    if isinstance(credential, BaseModel):
        # Convert to dictionary
        credential = credential.model_dump()

    # rawId must be decoded to bytes
    raw_id_bytes = base64url_to_bytes(credential["rawId"])
    # Build attestation response (only required fields)
    resp_dict = credential["response"]
    attestation_response = AuthenticatorAttestationResponse(
        client_data_json=base64url_to_bytes(resp_dict["clientDataJSON"]),
        attestation_object=base64url_to_bytes(resp_dict["attestationObject"]),
        transports=resp_dict.get("transports", []),  # optional; list[str]
    )

    # Map authenticatorAttachment -> authenticator_attachment enum if present
    attachment_str = credential.get("authenticatorAttachment")
    attachment_enum: Optional[AuthenticatorAttachment] = None
    if attachment_str == "platform":
        attachment_enum = AuthenticatorAttachment.PLATFORM
    elif attachment_str == "cross-platform":
        attachment_enum = AuthenticatorAttachment.CROSS_PLATFORM

    return RegistrationCredential(
        id=credential["id"],  # base64url string
        raw_id=raw_id_bytes,  # bytes
        response=attestation_response,
        authenticator_attachment=attachment_enum,
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )


def to_authentication_credential(credential_dict: dict) -> AuthenticationCredential:
    """
    Convert credential dictionary into a AuthenticationCredential model.
    """
    raw_id_bytes = base64url_to_bytes(credential_dict["rawId"])
    resp_dict = credential_dict["response"]
    assertion_response = AuthenticatorAssertionResponse(
        client_data_json=base64url_to_bytes(resp_dict["clientDataJSON"]),
        authenticator_data=base64url_to_bytes(resp_dict["authenticatorData"]),
        signature=base64url_to_bytes(resp_dict["signature"]),
        user_handle=(
            base64url_to_bytes(resp_dict["userHandle"])
            if resp_dict.get("userHandle")
            else None
        ),
    )
    return AuthenticationCredential(
        id=credential_dict["id"],
        raw_id=raw_id_bytes,
        response=assertion_response,
        authenticator_attachment=None,  # optional; map if you want using the same logic
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )


def serialise_options(obj) -> Union[dict, list, str]:
    """
    Convert Options to serialised objects
    """
    if is_dataclass(obj):
        obj = asdict(obj)

    # Bytes → base64url
    if isinstance(obj, (bytes, bytearray)):
        return bytes_to_base64url(bytes(obj))

    # Dict → recursively serialize values
    if isinstance(obj, dict):
        return {k: serialise_options(v) for k, v in obj.items()}

    # List/Tuple → recursively serialize items
    if isinstance(obj, (list, tuple)):
        return [serialise_options(v) for v in obj]

    # Other primitives are fine
    return obj


@router.get("/register/challenge/", description="Get Challenge for User Registration")
async def register_challenge(user_name: str) -> RegisterChallenge:
    """
    Registers a new user.

    Arguments:
        user_name: string of username to register.

    Returns:
        RegistrationChallenge

    Raises:
        RequestValidationError
    """

    if not user_name:
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "user_name"],
                    "msg": "no user_name specified",
                    "type": ValueError.__name__,
                }
            ]
        )

    if users_db.user_exists(user_name):
        # We need to check this BEFORE we raise a registration challenge.
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "user_name"],
                    "msg": "user_name already registered",
                    "type": ValueError.__name__,
                }
            ]
        )

    try:
        options: PublicKeyCredentialCreationOptions = generate_registration_options(
            rp_id=get_host_name(Insert.RP_ID),
            rp_name=os.getenv("APP_NAME", "FastKey Authenticator"),
            user_id=user_name.encode("utf-8"),
            user_name=user_name,
        )
    except ValueError as err:
        raise RequestValidationError(  # pylint: disable=raise-missing-from
            errors=[
                {
                    "loc": ["query", "user_name"],
                    "msg": str(err),
                    "type": err.__class__.__name__,
                }
            ]
        )

    # Store challenge as base64url string for later verification
    challenges_db[user_name] = bytes_to_base64url(options.challenge)

    # Serialize to JSON-safe structure (bytes→base64url)
    return RegisterChallenge(**serialise_options(options))


@router.post(
    "/register/challenge/", description="Respond to challenge for User Registration"
)
async def register_challenge_response(
    registration_request: RegisterRequest,
) -> ChallengeAccepted:
    """
    Register a user via RegisterRequest model attestation.

    Arguments:
        registration_request

    Returns:
        JSONResponse

    Raises:
        RequestValidationError
    """
    username = registration_request.username

    if users_db.user_exists(username):
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "username"],
                    "msg": "Specified username already registered",
                    "type": "value_error",
                }
            ]
        )

    if username not in challenges_db:
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "username"],
                    "msg": "Challenge for specified username does not exist or has expired",
                    "type": "value_error",
                }
            ]
        )

    # Build py_webauthn dataclass
    registration_credential = to_registration_credential(
        registration_request.credential
    )

    # Verify registration response
    verification = verify_registration_response(
        credential=registration_credential,
        expected_challenge=base64url_to_bytes(
            challenges_db.pop(username)
        ),  # base64url string stored earlier
        expected_rp_id=get_host_name(Insert.RP_ID),
        # adjust to your frontend origin
        expected_origin=get_host_name(Insert.ORIGIN),
    )

    # Persist credential info for login
    users_db[username] = {
        "credential_id": verification.credential_id,  # base64url string
        "public_key": verification.credential_public_key,  # COSE key, base64url
        "sign_count": verification.sign_count,
        "rp_id": get_host_name(Insert.RP_ID),
    }

    return ChallengeAccepted(message="User registered successfully.")


@router.get("/login/challenge/")
async def login_challenge(user_name: str) -> LoginChallenge:
    """
    Generate Authentication Options to a Login ChallengeRequest.
    """

    if not users_db.user_exists(user_name):
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "username"],
                    "msg": "user_name does not exist",
                    "type": ValueError.__name__,
                }
            ]
        )

    cred_id_b64u = users_db[user_name]["credential_id"]

    options = generate_authentication_options(
        rp_id=get_host_name(Insert.RP_ID),
        allow_credentials=[PublicKeyCredentialDescriptor(id=cred_id_b64u)],
    )

    # Store challenge as base64url string for later verification
    challenges_db[user_name] = bytes_to_base64url(options.challenge)

    return LoginChallenge(**serialise_options(options))


@router.post("/login/challenge/")
async def login_challenge_response(
    assertion_response: LoginRequest,
) -> ChallengeAccepted:
    """
    Authenticate Passkey assertion response via LoginRequest model.
    """
    username = assertion_response.username
    if not users_db.user_exists(username):
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "username"],
                    "msg": "Specified username does not exist",
                    "type": "value_error",
                }
            ]
        )

    if username not in challenges_db:
        if not users_db.user_exists(username):
            raise RequestValidationError(
                errors=[
                    {
                        "loc": ["query", "username"],
                        "msg": "Challenge for specified username does not exist or has expired",
                        "type": "value_error",
                    }
                ]
            )

    credential_dict = assertion_response.credential.model_dump()
    auth_credential = to_authentication_credential(credential_dict)

    user = users_db[username]
    verification = verify_authentication_response(
        credential=auth_credential,
        expected_challenge=base64url_to_bytes(challenges_db.pop(username)),
        expected_rp_id=user["rp_id"],
        expected_origin=get_host_name(Insert.ORIGIN),
        credential_public_key=user["public_key"],
        credential_current_sign_count=user["sign_count"],
        require_user_verification=True,
    )

    if not verification.user_verified:
        raise RequestValidationError(
            errors=[
                {
                    "loc": ["query", "body"],
                    "msg": "User verification failed",
                    "type": "value_error",
                }
            ]
        )

    # Update sign counter
    users_db[username]["sign_count"] = verification.new_sign_count

    # Issue token or session as needed
    return ChallengeAccepted(message="Login successful.")


@router.get("/fastkey.js")
async def get_data(request: Request) -> HTMLResponse:
    """
    Returns Fastkey stock Javascript

    This function modifies the base URL if it has not already been called.
    This aligns the base url with the backend so there is no datatype mismatch.
    """
    global javascript, JAVASCRIPT_MODIFIED  # pylint: disable=global-statement
    if not JAVASCRIPT_MODIFIED:
        api_base_url = get_host_name(headers=request.headers)
        javascript = javascript.replace("{{API_BASE_URL}}", api_base_url)
        JAVASCRIPT_MODIFIED = True

    return HTMLResponse(status_code=200, content=javascript)
