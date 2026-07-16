from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db import connect
from app.ember_identity import _active_admin_member, _b64u_decode, _verify_signature


PROTOCOL = "ember-recovery-v1"
REQUEST_WINDOW = timedelta(minutes=5)
MAX_PAYLOAD_BYTES = 128 * 1024

router = APIRouter(prefix="/v1/ember/recovery-backups", tags=["Ember recovery"])


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_fresh_request(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("requestedAt is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("requestedAt must include a timezone")
    if abs(_now() - parsed.astimezone(UTC)) > REQUEST_WINDOW:
        raise ValueError("requestedAt is outside the authorization window")
    return parsed


def recovery_message(
    action: Literal["upload", "latest"],
    installation_id: str,
    member_id: str,
    controller_id: str,
    value: str,
    requested_at: str,
) -> bytes:
    return (
        f"{PROTOCOL}\n{action}\n{installation_id}\n{member_id}\n"
        f"{controller_id}\n{value}\n{requested_at}"
    ).encode("utf-8")


class RecoveryAuthorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    member_id: str = Field(alias="memberId", min_length=1, max_length=64)
    controller_id: str = Field(alias="controllerId", pattern=r"^[A-F0-9]{12}$")
    requested_at: str = Field(alias="requestedAt")
    client_signature: str = Field(alias="clientSignature")

    @field_validator("installation_id", "member_id")
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: str) -> str:
        _parse_fresh_request(value)
        return value

    @field_validator("client_signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        _b64u_decode(value, 64, "clientSignature")
        return value


class RecoveryBackupUpload(RecoveryAuthorization):
    backup_id: str = Field(alias="backupId")
    backup_kind: Literal["oelo_configuration", "ember_rollback"] = Field(alias="backupKind")
    hardware_profile: Literal["oelo_esp32"] = Field(alias="hardwareProfile")
    format_version: Literal[1] = Field(alias="formatVersion")
    payload: str = Field(min_length=1, max_length=180_000)
    payload_digest: str = Field(alias="payloadDigest", pattern=r"^[a-f0-9]{64}$")
    captured_at: str = Field(alias="capturedAt")

    @field_validator("backup_id")
    @classmethod
    def validate_backup_id(cls, value: str) -> str:
        UUID(value)
        return value

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        decoded = _b64u_decode_variable(value, "payload")
        if len(decoded) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload is too large")
        return value

    @field_validator("captured_at")
    @classmethod
    def validate_captured_at(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("capturedAt must include a timezone")
        return value


class RecoveryBackupQuery(RecoveryAuthorization):
    backup_kind: Literal["oelo_configuration", "ember_rollback"] = Field(alias="backupKind")


class RecoveryBackupResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str = PROTOCOL
    backup_id: str = Field(alias="backupId")
    backup_kind: str = Field(alias="backupKind")
    controller_id: str = Field(alias="controllerId")
    hardware_profile: str = Field(alias="hardwareProfile")
    format_version: int = Field(alias="formatVersion")
    payload: str | None = None
    payload_digest: str = Field(alias="payloadDigest")
    captured_at: str = Field(alias="capturedAt")
    stored_at: str = Field(alias="storedAt")


def _b64u_decode_variable(value: str, field: str) -> bytes:
    import base64

    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(f"{field} is not valid base64url") from exc


def _authorize(conn: sqlite3.Connection, request: RecoveryAuthorization, action: Literal["upload", "latest"], value: str):
    member = _active_admin_member(conn, request.installation_id, request.member_id)
    try:
        _verify_signature(
            member["public_key"],
            request.client_signature,
            recovery_message(
                action,
                request.installation_id,
                request.member_id,
                request.controller_id,
                value,
                request.requested_at,
            ),
            "clientSignature",
        )
    except (InvalidSignature, ValueError):
        raise HTTPException(status_code=403, detail="Recovery authorization is invalid.") from None
    controller = conn.execute(
        """
        SELECT 1 FROM ember_members
        WHERE installation_id = ? AND kind = 'controller' AND subject_id = ?
          AND revoked_at IS NULL
        """,
        (request.installation_id, request.controller_id),
    ).fetchone()
    if not controller:
        raise HTTPException(status_code=403, detail="Controller is not an active installation member.")
    return member


@router.post("", response_model=RecoveryBackupResponse)
def upload_recovery_backup(request: RecoveryBackupUpload) -> RecoveryBackupResponse:
    payload_bytes = _b64u_decode_variable(request.payload, "payload")
    digest = hashlib.sha256(payload_bytes).hexdigest()
    if digest != request.payload_digest:
        raise HTTPException(status_code=400, detail="Recovery payload digest does not match.")
    now = _iso(_now())
    with connect() as conn:
        member = _authorize(
            conn,
            request,
            "upload",
            f"{request.payload_digest}:{request.backup_kind}:{request.backup_id}:{request.captured_at}",
        )
        existing = conn.execute(
            "SELECT * FROM ember_recovery_backups WHERE id = ?", (request.backup_id,)
        ).fetchone()
        if existing:
            if (
                existing["installation_id"] != request.installation_id
                or existing["controller_id"] != request.controller_id
                or existing["backup_kind"] != request.backup_kind
                or existing["payload_digest"] != request.payload_digest
            ):
                raise HTTPException(status_code=409, detail="Recovery backup identifier already exists.")
            row = existing
        else:
            conn.execute(
                """
                INSERT INTO ember_recovery_backups
                    (id, installation_id, controller_id, backup_kind, hardware_profile,
                     format_version, payload_json, payload_digest, captured_at,
                     created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.backup_id,
                    request.installation_id,
                    request.controller_id,
                    request.backup_kind,
                    request.hardware_profile,
                    request.format_version,
                    request.payload,
                    request.payload_digest,
                    request.captured_at,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO ember_audit_events
                    (installation_id, actor_member_id, event_type, subject_id,
                     detail_json, created_at)
                VALUES (?, ?, 'recovery_backup_stored', ?, ?, ?)
                """,
                (
                    request.installation_id,
                    member["id"],
                    request.controller_id,
                    json.dumps({"backupId": request.backup_id, "payloadDigest": digest}, separators=(",", ":")),
                    now,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM ember_recovery_backups WHERE id = ?", (request.backup_id,)
            ).fetchone()
    return _response(row, include_payload=False)


@router.post("/latest", response_model=RecoveryBackupResponse)
def latest_recovery_backup(request: RecoveryBackupQuery) -> RecoveryBackupResponse:
    with connect() as conn:
        _authorize(conn, request, "latest", f"latest:{request.backup_kind}")
        row = conn.execute(
            """
            SELECT * FROM ember_recovery_backups
            WHERE installation_id = ? AND controller_id = ? AND backup_kind = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (request.installation_id, request.controller_id, request.backup_kind),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No recovery backup is available for this controller.")
    return _response(row, include_payload=True)


def _response(row, *, include_payload: bool) -> RecoveryBackupResponse:
    return RecoveryBackupResponse(
        backupId=row["id"],
        backupKind=row["backup_kind"],
        controllerId=row["controller_id"],
        hardwareProfile=row["hardware_profile"],
        formatVersion=row["format_version"],
        payload=row["payload_json"] if include_payload else None,
        payloadDigest=row["payload_digest"],
        capturedAt=row["captured_at"],
        storedAt=row["created_at"],
    )
