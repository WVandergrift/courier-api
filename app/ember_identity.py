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


def _verify_controller_signature(public_key: str, signature: str, message: bytes) -> None:
    point = _b64u_decode(public_key, 65, "controller public key")
    raw_signature = _b64u_decode(signature, 64, "controllerSignature")
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    if r == 0 or s == 0:
        raise InvalidSignature
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))


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
                and bootstrap["tag_id"] == request.tag_id
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
        conn.execute(
            """
            INSERT INTO ember_enrollment_challenges
                (id, controller_id, tag_id, proof_method, client_public_key,
                 client_key_thumbprint, controller_public_key, hardware_model,
                 retrofit, server_nonce, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        _verify_controller_signature(
            challenge["controller_public_key"],
            request.controller_signature,
            message,
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
                bootstrap["tag_id"] != current["tag_id"]
                or bootstrap["public_key"] != current["controller_public_key"]
                or bootstrap["status"] != "active"
            ):
                raise HTTPException(status_code=409, detail="Controller enrollment identity changed.")

            controller_member = conn.execute(
                "SELECT * FROM ember_members WHERE kind = 'controller' AND subject_id = ?",
                (current["controller_id"],),
            ).fetchone()
            created_installation = controller_member is None
            if controller_member and controller_member["revoked_at"]:
                raise HTTPException(status_code=403, detail="Controller membership is revoked.")

            if created_installation:
                installation_id = str(uuid4())
                controller_member_id = str(uuid4())
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
                installation_id = controller_member["installation_id"]
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
                    controller_member_id,
                    "installation_created" if created_installation else "client_enrolled",
                    member_id,
                    json.dumps({"challengeId": challenge_id}, separators=(",", ":")),
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
