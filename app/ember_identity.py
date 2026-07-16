from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth import require_auth
from app.db import connect


PROTOCOL = "ember-installation-v1"
CHALLENGE_LIFETIME = timedelta(minutes=2)
CONTROLLER_ADD_GRANT_LIFETIME = timedelta(minutes=5)
CONTROLLER_CAPABILITIES = ["approve_clients", "sync_controller_documents"]
CLIENT_CAPABILITIES = ["admin", "sync_installation_documents"]

router = APIRouter(prefix="/v1/ember", tags=["Ember installations"])


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: str, expected_length: int, field: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(f"{field} is not valid base64url") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"{field} must decode to {expected_length} bytes")
    return decoded


def _normalize_public_key(value: str) -> str:
    raw = _b64u_decode(value, 65, "public key")
    if raw[0] != 0x04:
        raise ValueError("public key must be an uncompressed P-256 point")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise ValueError("public key is not on P-256") from exc
    return _b64u_encode(raw)


def key_thumbprint(public_key: str) -> str:
    return _b64u_encode(hashlib.sha256(_b64u_decode(public_key, 65, "public key")).digest())


def synthetic_controller_tag(controller_id: str) -> str:
    return f"controller_{controller_id}"


def bootstrap_tag_matches(bootstrap, controller_id: str, tag_id: str) -> bool:
    return bootstrap["tag_id"] == tag_id or tag_id == synthetic_controller_tag(controller_id)


def enrollment_message(
    proof_method: str,
    challenge_id: str,
    controller_id: str,
    tag_id: str,
    client_key_thumbprint: str,
    server_nonce: str,
) -> bytes:
    return (
        "ember-courier-enrollment/v1\n"
        f"{proof_method}\n"
        f"{challenge_id}\n"
        f"{controller_id}\n"
        f"{tag_id}\n"
        f"{client_key_thumbprint}\n"
        f"{server_nonce}"
    ).encode("utf-8")


def _verify_signature(public_key: str, signature: str, message: bytes, field: str) -> None:
    point = _b64u_decode(public_key, 65, "controller public key")
    raw_signature = _b64u_decode(signature, 64, field)
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    if r == 0 or s == 0:
        raise InvalidSignature
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))


def controller_add_grant_message(
    grant_id: str,
    installation_id: str,
    authorizer_member_id: str,
    controller_id: str,
    controller_key_thumbprint: str,
    tag_id: str,
    hardware_model: str,
    client_key_thumbprint: str,
    server_nonce: str,
    expires_at: str,
) -> bytes:
    return (
        "ember-controller-add-grant/v1\n"
        f"{grant_id}\n"
        f"{installation_id}\n"
        f"{authorizer_member_id}\n"
        f"{controller_id}\n"
        f"{controller_key_thumbprint}\n"
        f"{tag_id}\n"
        f"{hardware_model}\n"
        f"{client_key_thumbprint}\n"
        f"{server_nonce}\n"
        f"{expires_at}"
    ).encode("utf-8")


class ControllerBootstrapRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    controller_id: str = Field(alias="controllerId", pattern=r"^[A-F0-9]{12}$")
    tag_id: str = Field(alias="tagId", min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    public_key: str = Field(alias="publicKey")
    hardware_model: str = Field(alias="hardwareModel", min_length=1, max_length=64)
    attestation: Literal["factory", "retrofit"] = "factory"
    key_version: int = Field(default=1, alias="keyVersion", ge=1, le=255)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _normalize_public_key(value)


class ControllerBootstrapResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    controller_id: str = Field(alias="controllerId")
    tag_id: str = Field(alias="tagId")
    status: str
    created: bool


class EnrollmentChallengeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    controller_id: str = Field(alias="controllerId", pattern=r"^[A-F0-9]{12}$")
    tag_id: str = Field(alias="tagId", min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    proof_method: Literal["home_key_ble", "controller_button"] = Field(alias="proofMethod")
    client_public_key: str = Field(alias="clientPublicKey")
    controller_public_key: str | None = Field(default=None, alias="controllerPublicKey")
    hardware_model: str | None = Field(default=None, alias="hardwareModel", min_length=1, max_length=64)
    controller_add_grant_id: str | None = Field(default=None, alias="controllerAddGrantId")

    @field_validator("client_public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _normalize_public_key(value)

    @field_validator("controller_public_key")
    @classmethod
    def validate_controller_public_key(cls, value: str | None) -> str | None:
        return _normalize_public_key(value) if value is not None else None


class EnrollmentChallengeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    proof_method: str = Field(alias="proofMethod")
    challenge_id: str = Field(alias="challengeId")
    server_nonce: str = Field(alias="serverNonce")
    expires_at: str = Field(alias="expiresAt")


class EnrollmentCompleteRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    controller_signature: str = Field(alias="controllerSignature")
    client_name: str = Field(alias="clientName", min_length=1, max_length=64)

    @field_validator("controller_signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        _b64u_decode(value, 64, "controllerSignature")
        return value

    @field_validator("client_name")
    @classmethod
    def normalize_client_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("clientName is required")
        return normalized


class EnrollmentCompleteResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    installation_id: str = Field(alias="installationId")
    member_id: str = Field(alias="memberId")
    controller_member_id: str = Field(alias="controllerMemberId")
    created_installation: bool = Field(alias="createdInstallation")


class ControllerAddGrantRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    authorizer_member_id: str = Field(alias="authorizerMemberId", min_length=1, max_length=64)
    controller_id: str = Field(alias="controllerId", pattern=r"^[A-F0-9]{12}$")
    controller_public_key: str = Field(alias="controllerPublicKey")
    tag_id: str = Field(alias="tagId", min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    hardware_model: str = Field(alias="hardwareModel", min_length=1, max_length=64)

    @field_validator("controller_public_key")
    @classmethod
    def validate_controller_public_key(cls, value: str) -> str:
        return _normalize_public_key(value)


class ControllerAddGrantResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    grant_id: str = Field(alias="grantId")
    server_nonce: str = Field(alias="serverNonce")
    expires_at: str = Field(alias="expiresAt")


class ControllerAddGrantAuthorizeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_signature: str = Field(alias="clientSignature")

    @field_validator("client_signature")
    @classmethod
    def validate_client_signature(cls, value: str) -> str:
        _b64u_decode(value, 64, "clientSignature")
        return value


class ControllerAddGrantAuthorizeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    grant_id: str = Field(alias="grantId")
    authorized: bool
    expires_at: str = Field(alias="expiresAt")


def _active_admin_member(conn: sqlite3.Connection, installation_id: str, member_id: str):
    member = conn.execute(
        """
        SELECT m.*, i.status AS installation_status
        FROM ember_members m
        JOIN ember_installations i ON i.id = m.installation_id
        WHERE m.id = ? AND m.installation_id = ?
        """,
        (member_id, installation_id),
    ).fetchone()
    if (
        not member
        or member["kind"] != "client"
        or member["revoked_at"]
        or member["installation_status"] != "active"
        or "admin" not in json.loads(member["capabilities_json"])
    ):
        raise HTTPException(status_code=403, detail="Controller authorization is unavailable.")
    return member


@router.post("/controller-add-grants", response_model=ControllerAddGrantResponse)
def create_controller_add_grant(request: ControllerAddGrantRequest) -> ControllerAddGrantResponse:
    now = _now()
    expires_at = now + CONTROLLER_ADD_GRANT_LIFETIME
    expires_at_text = _iso(expires_at)
    grant_id = str(uuid4())
    server_nonce = _b64u_encode(secrets.token_bytes(32))
    controller_thumbprint = key_thumbprint(request.controller_public_key)

    with connect() as conn:
        authorizer = _active_admin_member(
            conn, request.installation_id, request.authorizer_member_id
        )
        claimed = conn.execute(
            "SELECT installation_id, revoked_at FROM ember_members WHERE kind = 'controller' AND subject_id = ?",
            (request.controller_id,),
        ).fetchone()
        if claimed and (
            claimed["installation_id"] != request.installation_id
            or claimed["revoked_at"]
        ):
            raise HTTPException(status_code=409, detail="Controller already belongs to an installation.")
        if claimed:
            member_identity = conn.execute(
                "SELECT public_key FROM ember_members WHERE kind = 'controller' AND subject_id = ?",
                (request.controller_id,),
            ).fetchone()
            if not member_identity or member_identity["public_key"] != request.controller_public_key:
                raise HTTPException(status_code=409, detail="Controller membership identity changed.")

        bootstrap = conn.execute(
            "SELECT * FROM ember_controller_bootstraps WHERE controller_id = ? OR tag_id = ?",
            (request.controller_id, request.tag_id),
        ).fetchone()
        if bootstrap and not (
            bootstrap["controller_id"] == request.controller_id
            and bootstrap_tag_matches(bootstrap, request.controller_id, request.tag_id)
            and bootstrap["public_key"] == request.controller_public_key
            and bootstrap["hardware_model"] == request.hardware_model
            and bootstrap["status"] == "active"
        ):
            raise HTTPException(status_code=409, detail="Controller authorization identity conflicts with an existing registration.")

        conn.execute(
            """
            INSERT INTO ember_controller_add_grants
                (id, installation_id, authorizer_member_id, controller_id,
                 controller_public_key, controller_key_thumbprint, tag_id,
                 hardware_model, client_key_thumbprint, server_nonce, created_at,
                 expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                grant_id, request.installation_id, request.authorizer_member_id,
                request.controller_id, request.controller_public_key,
                controller_thumbprint, request.tag_id, request.hardware_model,
                authorizer["key_thumbprint"], server_nonce, _iso(now),
                expires_at_text,
            ),
        )
        conn.commit()

    return ControllerAddGrantResponse(
        protocol=PROTOCOL,
        grantId=grant_id,
        serverNonce=server_nonce,
        expiresAt=expires_at_text,
    )


@router.post(
    "/controller-add-grants/{grant_id}/authorize",
    response_model=ControllerAddGrantAuthorizeResponse,
)
def authorize_controller_add_grant(
    grant_id: str, request: ControllerAddGrantAuthorizeRequest
) -> ControllerAddGrantAuthorizeResponse:
    with connect() as conn:
        grant = conn.execute(
            "SELECT * FROM ember_controller_add_grants WHERE id = ?", (grant_id,)
        ).fetchone()
        if not grant:
            raise HTTPException(status_code=404, detail="Controller authorization is unavailable.")
        authorizer = _active_admin_member(
            conn, grant["installation_id"], grant["authorizer_member_id"]
        )
    if grant["consumed_at"]:
        raise HTTPException(status_code=409, detail="Controller authorization was already used.")
    if grant["authorized_at"]:
        raise HTTPException(status_code=409, detail="Controller authorization was already approved.")
    if _parse_iso(grant["expires_at"]) <= _now():
        raise HTTPException(status_code=410, detail="Controller authorization expired.")

    message = controller_add_grant_message(
        grant["id"], grant["installation_id"], grant["authorizer_member_id"],
        grant["controller_id"], grant["controller_key_thumbprint"], grant["tag_id"],
        grant["hardware_model"], grant["client_key_thumbprint"], grant["server_nonce"],
        grant["expires_at"],
    )
    try:
        _verify_signature(authorizer["public_key"], request.client_signature, message, "clientSignature")
    except (ValueError, InvalidSignature):
        raise HTTPException(status_code=403, detail="Controller authorization signature is invalid.") from None

    now = _iso(_now())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT * FROM ember_controller_add_grants WHERE id = ?", (grant_id,)
        ).fetchone()
        if not current or current["authorized_at"] or current["consumed_at"]:
            raise HTTPException(status_code=409, detail="Controller authorization was already used.")
        if _parse_iso(current["expires_at"]) <= _now():
            raise HTTPException(status_code=410, detail="Controller authorization expired.")
        current_authorizer = _active_admin_member(
            conn, current["installation_id"], current["authorizer_member_id"]
        )
        if current_authorizer["key_thumbprint"] != current["client_key_thumbprint"]:
            raise HTTPException(status_code=409, detail="Controller authorization identity changed.")
        conn.execute(
            "UPDATE ember_controller_add_grants SET authorized_at = ? WHERE id = ?",
            (now, grant_id),
        )
        conn.commit()

    return ControllerAddGrantAuthorizeResponse(
        protocol=PROTOCOL, grantId=grant_id, authorized=True,
        expiresAt=grant["expires_at"],
    )


@router.post(
    "/controller-bootstraps",
    response_model=ControllerBootstrapResponse,
    dependencies=[Depends(require_auth)],
)
def register_controller_bootstrap(request: ControllerBootstrapRequest) -> ControllerBootstrapResponse:
    now = _iso(_now())
    with connect() as conn:
        existing = conn.execute(
            "SELECT * FROM ember_controller_bootstraps WHERE controller_id = ? OR tag_id = ?",
            (request.controller_id, request.tag_id),
        ).fetchone()
        if existing:
            exact = (
                existing["controller_id"] == request.controller_id
                and existing["tag_id"] == request.tag_id
                and existing["public_key"] == request.public_key
                and existing["hardware_model"] == request.hardware_model
                and existing["attestation"] == request.attestation
                and existing["key_version"] == request.key_version
            )
            if not exact:
                raise HTTPException(status_code=409, detail="Controller or NFC tag is already registered.")
            return ControllerBootstrapResponse(
                controllerId=existing["controller_id"],
                tagId=existing["tag_id"],
                status=existing["status"],
                created=False,
            )

        conn.execute(
            """
            INSERT INTO ember_controller_bootstraps
                (controller_id, tag_id, public_key, hardware_model, attestation,
                 key_version, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                request.controller_id,
                request.tag_id,
                request.public_key,
                request.hardware_model,
                request.attestation,
                request.key_version,
                now,
                now,
            ),
        )
        conn.commit()
    return ControllerBootstrapResponse(
        controllerId=request.controller_id,
        tagId=request.tag_id,
        status="active",
        created=True,
    )


@router.post("/enrollment-challenges", response_model=EnrollmentChallengeResponse)
def begin_enrollment(request: EnrollmentChallengeRequest) -> EnrollmentChallengeResponse:
    now = _now()
    expires_at = now + CHALLENGE_LIFETIME
    challenge_id = str(uuid4())
    server_nonce = _b64u_encode(secrets.token_bytes(32))
    thumbprint = key_thumbprint(request.client_public_key)

    with connect() as conn:
        bootstrap = conn.execute(
            """
            SELECT * FROM ember_controller_bootstraps
            WHERE controller_id = ? OR tag_id = ?
            """,
            (request.controller_id, request.tag_id),
        ).fetchone()
        retrofit = bootstrap is None
        if bootstrap:
            exact_identity = (
                bootstrap["controller_id"] == request.controller_id
                and (
                    bootstrap["tag_id"] == request.tag_id
                    or (
                        request.proof_method == "controller_button"
                        and request.tag_id == synthetic_controller_tag(request.controller_id)
                    )
                )
                and bootstrap["status"] == "active"
            )
            key_matches = (
                request.controller_public_key is None
                or bootstrap["public_key"] == request.controller_public_key
            )
            if not exact_identity or not key_matches:
                raise HTTPException(status_code=409, detail="Controller enrollment identity conflicts with an existing registration.")
        else:
            if request.controller_public_key is None or request.hardware_model is None:
                raise HTTPException(status_code=404, detail="Controller enrollment is unavailable.")
        controller_public_key = (
            bootstrap["public_key"] if bootstrap else request.controller_public_key
        )
        hardware_model = (
            bootstrap["hardware_model"] if bootstrap else request.hardware_model
        )
        if request.controller_add_grant_id:
            grant = conn.execute(
                "SELECT * FROM ember_controller_add_grants WHERE id = ?",
                (request.controller_add_grant_id,),
            ).fetchone()
            if (
                not grant
                or not grant["authorized_at"]
                or grant["consumed_at"]
                or _parse_iso(grant["expires_at"]) <= now
            ):
                raise HTTPException(status_code=403, detail="Controller authorization is unavailable.")
            if not (
                grant["controller_id"] == request.controller_id
                and grant["controller_public_key"] == controller_public_key
                and grant["tag_id"] == request.tag_id
                and grant["hardware_model"] == hardware_model
                and grant["client_key_thumbprint"] == thumbprint
            ):
                raise HTTPException(status_code=409, detail="Controller authorization does not match this enrollment.")
            _active_admin_member(
                conn, grant["installation_id"], grant["authorizer_member_id"]
            )
        conn.execute(
            """
            INSERT INTO ember_enrollment_challenges
                (id, controller_id, tag_id, proof_method, client_public_key,
                 client_key_thumbprint, controller_public_key, hardware_model,
                 retrofit, controller_add_grant_id, server_nonce, created_at,
                 expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge_id,
                request.controller_id,
                request.tag_id,
                request.proof_method,
                request.client_public_key,
                thumbprint,
                controller_public_key,
                hardware_model,
                1 if retrofit else 0,
                request.controller_add_grant_id,
                server_nonce,
                _iso(now),
                _iso(expires_at),
            ),
        )
        conn.commit()

    return EnrollmentChallengeResponse(
        protocol=PROTOCOL,
        proofMethod=request.proof_method,
        challengeId=challenge_id,
        serverNonce=server_nonce,
        expiresAt=_iso(expires_at),
    )


@router.post(
    "/enrollment-challenges/{challenge_id}/complete",
    response_model=EnrollmentCompleteResponse,
)
def complete_enrollment(challenge_id: str, request: EnrollmentCompleteRequest) -> EnrollmentCompleteResponse:
    with connect() as conn:
        challenge = conn.execute(
            "SELECT * FROM ember_enrollment_challenges WHERE id = ?",
            (challenge_id,),
        ).fetchone()
    if not challenge:
        raise HTTPException(status_code=404, detail="Enrollment challenge is unavailable.")
    if challenge["consumed_at"]:
        raise HTTPException(status_code=409, detail="Enrollment challenge was already used.")
    if _parse_iso(challenge["expires_at"]) <= _now():
        raise HTTPException(status_code=410, detail="Enrollment challenge expired.")

    message = enrollment_message(
        challenge["proof_method"],
        challenge["id"],
        challenge["controller_id"],
        challenge["tag_id"],
        challenge["client_key_thumbprint"],
        challenge["server_nonce"],
    )
    try:
        _verify_signature(
            challenge["controller_public_key"],
            request.controller_signature,
            message,
            "controllerSignature",
        )
    except (ValueError, InvalidSignature):
        raise HTTPException(status_code=403, detail="Controller approval is invalid.") from None

    now = _iso(_now())
    try:
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                "SELECT * FROM ember_enrollment_challenges WHERE id = ?",
                (challenge_id,),
            ).fetchone()
            if not current or current["consumed_at"]:
                raise HTTPException(status_code=409, detail="Enrollment challenge was already used.")
            if _parse_iso(current["expires_at"]) <= _now():
                raise HTTPException(status_code=410, detail="Enrollment challenge expired.")

            bootstrap = conn.execute(
                "SELECT * FROM ember_controller_bootstraps WHERE controller_id = ?",
                (current["controller_id"],),
            ).fetchone()
            if current["retrofit"]:
                if bootstrap:
                    exact = (
                        bootstrap["tag_id"] == current["tag_id"]
                        and bootstrap["public_key"] == current["controller_public_key"]
                        and bootstrap["hardware_model"] == current["hardware_model"]
                        and bootstrap["status"] == "active"
                    )
                    if not exact:
                        raise HTTPException(status_code=409, detail="Controller enrollment identity changed.")
                else:
                    tag_conflict = conn.execute(
                        "SELECT 1 FROM ember_controller_bootstraps WHERE tag_id = ?",
                        (current["tag_id"],),
                    ).fetchone()
                    if tag_conflict:
                        raise HTTPException(status_code=409, detail="Controller enrollment identity changed.")
                    conn.execute(
                        """
                        INSERT INTO ember_controller_bootstraps
                            (controller_id, tag_id, public_key, hardware_model,
                             attestation, key_version, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, 'retrofit', 1, 'active', ?, ?)
                        """,
                        (
                            current["controller_id"], current["tag_id"],
                            current["controller_public_key"], current["hardware_model"],
                            now, now,
                        ),
                    )
            elif not bootstrap or (
                not bootstrap_tag_matches(
                    bootstrap, current["controller_id"], current["tag_id"]
                )
                or bootstrap["public_key"] != current["controller_public_key"]
                or bootstrap["status"] != "active"
            ):
                raise HTTPException(status_code=409, detail="Controller enrollment identity changed.")

            controller_member = conn.execute(
                "SELECT * FROM ember_members WHERE kind = 'controller' AND subject_id = ?",
                (current["controller_id"],),
            ).fetchone()
            grant = None
            authorizer = None
            if current["controller_add_grant_id"]:
                grant = conn.execute(
                    "SELECT * FROM ember_controller_add_grants WHERE id = ?",
                    (current["controller_add_grant_id"],),
                ).fetchone()
                if (
                    not grant
                    or not grant["authorized_at"]
                    or grant["consumed_at"]
                    or _parse_iso(grant["expires_at"]) <= _now()
                ):
                    raise HTTPException(status_code=403, detail="Controller authorization is unavailable.")
                if not (
                    grant["controller_id"] == current["controller_id"]
                    and grant["controller_public_key"] == current["controller_public_key"]
                    and grant["tag_id"] == current["tag_id"]
                    and grant["hardware_model"] == current["hardware_model"]
                    and grant["client_key_thumbprint"] == current["client_key_thumbprint"]
                ):
                    raise HTTPException(status_code=409, detail="Controller authorization identity changed.")
                authorizer = _active_admin_member(
                    conn, grant["installation_id"], grant["authorizer_member_id"]
                )
                if authorizer["key_thumbprint"] != grant["client_key_thumbprint"]:
                    raise HTTPException(status_code=409, detail="Controller authorization identity changed.")

            if grant and controller_member and (
                controller_member["installation_id"] != grant["installation_id"]
                or controller_member["public_key"] != current["controller_public_key"]
                or controller_member["revoked_at"]
            ):
                raise HTTPException(status_code=409, detail="Controller already belongs to an installation.")
            created_installation = controller_member is None and grant is None
            if controller_member and controller_member["revoked_at"]:
                raise HTTPException(status_code=403, detail="Controller membership is revoked.")

            if created_installation or (grant and not controller_member):
                installation_id = grant["installation_id"] if grant else str(uuid4())
                controller_member_id = str(uuid4())
                if created_installation:
                    conn.execute(
                        """
                        INSERT INTO ember_installations (id, status, revision, created_at, updated_at)
                        VALUES (?, 'active', 1, ?, ?)
                        """,
                        (installation_id, now, now),
                    )
                conn.execute(
                    """
                    INSERT INTO ember_members
                        (id, installation_id, kind, subject_id, public_key,
                         key_thumbprint, display_name, capabilities_json,
                         created_at, updated_at)
                    VALUES (?, ?, 'controller', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        controller_member_id,
                        installation_id,
                        current["controller_id"],
                        current["controller_public_key"],
                        key_thumbprint(current["controller_public_key"]),
                        f"Ember Core {current['controller_id'][-4:]}",
                        json.dumps(CONTROLLER_CAPABILITIES, separators=(",", ":")),
                        now,
                        now,
                    ),
                )
            else:
                installation_id = grant["installation_id"] if grant else controller_member["installation_id"]
                controller_member_id = controller_member["id"]
                installation = conn.execute(
                    "SELECT status FROM ember_installations WHERE id = ?",
                    (installation_id,),
                ).fetchone()
                if not installation or installation["status"] != "active":
                    raise HTTPException(status_code=403, detail="Installation is unavailable.")

            existing_client = conn.execute(
                """
                SELECT * FROM ember_members
                WHERE installation_id = ? AND kind = 'client' AND key_thumbprint = ?
                """,
                (installation_id, current["client_key_thumbprint"]),
            ).fetchone()
            if existing_client and existing_client["revoked_at"]:
                raise HTTPException(status_code=403, detail="Client membership is revoked.")
            if existing_client:
                member_id = existing_client["id"]
            else:
                member_id = str(uuid4())
                conn.execute(
                    """
                    INSERT INTO ember_members
                        (id, installation_id, kind, subject_id, public_key,
                         key_thumbprint, display_name, capabilities_json,
                         created_at, updated_at)
                    VALUES (?, ?, 'client', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        member_id,
                        installation_id,
                        current["client_key_thumbprint"],
                        current["client_public_key"],
                        current["client_key_thumbprint"],
                        request.client_name,
                        json.dumps(CLIENT_CAPABILITIES, separators=(",", ":")),
                        now,
                        now,
                    ),
                )

            if grant:
                if member_id != grant["authorizer_member_id"]:
                    raise HTTPException(status_code=409, detail="Controller authorization client changed.")
                conn.execute(
                    "UPDATE ember_controller_add_grants SET consumed_at = ? WHERE id = ?",
                    (now, grant["id"]),
                )

            conn.execute(
                "UPDATE ember_enrollment_challenges SET consumed_at = ? WHERE id = ?",
                (now, challenge_id),
            )
            conn.execute(
                """
                INSERT INTO ember_audit_events
                    (installation_id, actor_member_id, event_type, subject_id,
                     detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    installation_id,
                    member_id if grant else controller_member_id,
                    ("controller_recovered" if controller_member else "controller_added") if grant else (
                        "installation_created" if created_installation else "client_enrolled"
                    ),
                    controller_member_id if grant else member_id,
                    json.dumps(
                        {
                            "challengeId": challenge_id,
                            **({"controllerAddGrantId": grant["id"]} if grant else {}),
                        },
                        separators=(",", ":"),
                    ),
                    now,
                ),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Enrollment conflicted with another request.") from None

    return EnrollmentCompleteResponse(
        protocol=PROTOCOL,
        installationId=installation_id,
        memberId=member_id,
        controllerMemberId=controller_member_id,
        createdInstallation=created_installation,
    )
