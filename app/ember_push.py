from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.apns import ApnsClient, ApnsSend
from app.db import connect, insert_event
from app.ember_identity import _active_admin_member, _parse_iso, _verify_signature
from app.logging_config import log_fields, payload_summary, redact_token


PROTOCOL = "ember-member-push-v1"
EMBER_APNS_TOPIC = "app.embercore"
AUTHORIZATION_CLOCK_SKEW = timedelta(minutes=5)
router = APIRouter(prefix="/v1/ember", tags=["Ember push notifications"])
logger = logging.getLogger("courier.ember_push")
_apns_client: ApnsClient | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def configure_ember_push(client: ApnsClient | None) -> None:
    global _apns_client
    _apns_client = client


def member_push_token_message(
    action: str,
    installation_id: str,
    member_id: str,
    platform: str,
    environment: str,
    app_topic: str,
    device_token: str,
    requested_at: str,
) -> bytes:
    return (
        f"{PROTOCOL}\n{action}\n{installation_id}\n{member_id}\n{platform}\n"
        f"{environment}\n{app_topic}\n{device_token}\n{requested_at}"
    ).encode("utf-8")


class MemberPushTokenRegistration(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    member_id: str = Field(alias="memberId", min_length=1, max_length=64)
    platform: Literal["ios"]
    environment: Literal["sandbox", "production"]
    app_topic: Literal[EMBER_APNS_TOPIC] = Field(alias="appTopic")
    device_token: str = Field(alias="deviceToken", min_length=32, max_length=256)
    requested_at: str = Field(alias="requestedAt")
    client_signature: str = Field(alias="clientSignature")

    @field_validator("device_token")
    @classmethod
    def normalize_device_token(cls, value: str) -> str:
        normalized = "".join(value.split()).lower()
        if not all(character in "0123456789abcdef" for character in normalized):
            raise ValueError("deviceToken must be hexadecimal")
        return normalized

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: str) -> str:
        try:
            requested_at = _parse_iso(value)
        except ValueError as exc:
            raise ValueError("requestedAt is invalid") from exc
        if requested_at.tzinfo is None or abs(_now() - requested_at.astimezone(UTC)) > AUTHORIZATION_CLOCK_SKEW:
            raise ValueError("requestedAt is outside the authorization window")
        return value


def _token_cipher() -> Fernet:
    key = os.environ.get("EMBER_PUSH_TOKEN_KEY", "").strip()
    if not key:
        raise RuntimeError("EMBER_PUSH_TOKEN_KEY is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("EMBER_PUSH_TOKEN_KEY is invalid") from exc


def _encrypt_token(token: str) -> str:
    return _token_cipher().encrypt(token.encode("ascii")).decode("ascii")


def _decrypt_token(ciphertext: str) -> str:
    try:
        return _token_cipher().decrypt(ciphertext.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise RuntimeError("Stored member push token could not be decrypted") from exc


@router.post("/member-push-tokens")
def register_member_push_token(request: MemberPushTokenRegistration):
    try:
        ciphertext = _encrypt_token(request.device_token)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Member push token storage is unavailable.") from None

    now = _iso(_now())
    token_hash = hashlib.sha256(request.device_token.encode("ascii")).hexdigest()
    with connect() as conn:
        member = _active_admin_member(conn, request.installation_id, request.member_id)
        try:
            _verify_signature(
                member["public_key"],
                request.client_signature,
                member_push_token_message(
                    "register",
                    request.installation_id,
                    request.member_id,
                    request.platform,
                    request.environment,
                    request.app_topic,
                    request.device_token,
                    request.requested_at,
                ),
                "clientSignature",
            )
        except (InvalidSignature, ValueError):
            raise HTTPException(status_code=403, detail="Push token authorization is invalid.") from None

        # An APNs token identifies one app installation. If iOS restores or
        # rotates it onto a different Ember member, retire the previous owner
        # before making the new registration active.
        conn.execute(
            """
            UPDATE ember_member_push_tokens
            SET revoked_at = ?, updated_at = ?
            WHERE environment = ? AND app_topic = ? AND token_hash = ?
              AND member_id != ? AND revoked_at IS NULL
            """,
            (
                now,
                now,
                request.environment,
                request.app_topic,
                token_hash,
                request.member_id,
            ),
        )
        token_id = str(uuid4())
        conn.execute(
            """
            INSERT INTO ember_member_push_tokens
                (id, installation_id, member_id, platform, environment,
                 app_topic, token_ciphertext, token_hash, created_at,
                 updated_at, last_validated_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(member_id, platform, environment, app_topic) DO UPDATE SET
                installation_id = excluded.installation_id,
                token_ciphertext = excluded.token_ciphertext,
                token_hash = excluded.token_hash,
                updated_at = excluded.updated_at,
                last_validated_at = excluded.last_validated_at,
                revoked_at = NULL
            """,
            (
                token_id,
                request.installation_id,
                request.member_id,
                request.platform,
                request.environment,
                request.app_topic,
                ciphertext,
                token_hash,
                now,
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT id FROM ember_member_push_tokens
            WHERE member_id = ? AND platform = ? AND environment = ? AND app_topic = ?
            """,
            (request.member_id, request.platform, request.environment, request.app_topic),
        ).fetchone()
    return {"protocol": PROTOCOL, "tokenId": row["id"], "registered": True}


async def dispatch_join_request_pushes(installation_id: str, request_id: str) -> None:
    client = _apns_client
    if client is None:
        logger.error("ember_join_push_skipped", extra=log_fields(reason="apns_unavailable"))
        return
    with connect() as conn:
        request = conn.execute(
            """
            SELECT id, expires_at FROM ember_join_requests
            WHERE id = ? AND installation_id = ? AND status = 'pending'
            """,
            (request_id, installation_id),
        ).fetchone()
        tokens = conn.execute(
            """
            SELECT t.* FROM ember_member_push_tokens t
            JOIN ember_members m ON m.id = t.member_id
            JOIN ember_installations i ON i.id = t.installation_id
            WHERE t.installation_id = ? AND t.revoked_at IS NULL
              AND m.revoked_at IS NULL AND m.kind = 'client'
              AND i.status = 'active'
            """,
            (installation_id,),
        ).fetchall()
    if request is None:
        return

    payload = {
        "aps": {
            "alert": {
                "title": "Another device wants to join Ember",
                "body": "Open Ember to review the Home access request.",
            },
            "sound": "default",
            "category": "EMBER_HOME_ACCESS",
            "thread-id": "ember-home-access",
        },
        "kind": "ember-client-join",
        "requestId": request_id,
    }
    expiration = int(_parse_iso(request["expires_at"]).timestamp())
    for row in tokens:
        try:
            device_token = _decrypt_token(row["token_ciphertext"])
        except RuntimeError:
            logger.exception(
                "ember_join_push_token_unavailable",
                extra=log_fields(token_id=row["id"], member_id=row["member_id"]),
            )
            continue
        started = time.monotonic()
        try:
            result = await client.send(
                ApnsSend(
                    device_token=device_token,
                    topic=row["app_topic"],
                    environment=row["environment"],
                    payload=payload,
                    collapse_id=f"ember-join-{request_id}",
                    expiration=expiration,
                )
            )
            latency_ms = int((time.monotonic() - started) * 1000)
            insert_event(
                {
                    "environment": row["environment"],
                    "apns_topic": row["app_topic"],
                    # insert_event stores only a digest and short suffix; the
                    # plaintext token is not retained in the audit table.
                    "device_token": device_token,
                    "title": payload["aps"]["alert"]["title"],
                    "body": payload["aps"]["alert"]["body"],
                    "payload": payload,
                    "status": "sent" if result.success else "failed",
                    "provider_status_code": result.status_code,
                    "apns_id": result.apns_id,
                    "error_code": result.error_code,
                    "error_message": result.error_message,
                    "retryable": int(result.retryable),
                    "invalid_token": int(result.invalid_token),
                    "latency_ms": latency_ms,
                }
            )
            if result.invalid_token:
                with connect() as conn:
                    conn.execute(
                        "UPDATE ember_member_push_tokens SET revoked_at = ?, updated_at = ? WHERE id = ?",
                        (_iso(_now()), _iso(_now()), row["id"]),
                    )
                    conn.commit()
            logger.info(
                "ember_join_push_result",
                extra=log_fields(
                    request_id=request_id,
                    member_id=row["member_id"],
                    success=result.success,
                    invalid_token=result.invalid_token,
                    device_token=redact_token(device_token),
                    payload=payload_summary(payload),
                ),
            )
        except Exception:
            logger.exception(
                "ember_join_push_failed",
                extra=log_fields(
                    request_id=request_id,
                    member_id=row["member_id"],
                    device_token=redact_token(device_token),
                ),
            )
