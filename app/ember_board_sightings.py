from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db import connect
from app.ember_identity import _parse_iso, _verify_signature
from app.ember_push import dispatch_board_sighting_pushes


PROTOCOL = "ember-board-sighting-v1"
SIGNATURE_DOMAIN = "ember-board-sighting/v1"
OBSERVATION_CLOCK_SKEW = timedelta(minutes=10)
NOTIFICATION_DEDUPLICATION_WINDOW = timedelta(hours=24)

router = APIRouter(prefix="/v1/ember", tags=["Ember board sightings"])


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def board_sighting_message(
    controller_id: str,
    installation_id: str,
    board_name: str,
    board_suffix: str,
    observed_at: str,
    median_rssi: str,
) -> bytes:
    return (
        f"{SIGNATURE_DOMAIN}\n{controller_id}\n{installation_id}\n{board_name}\n"
        f"{board_suffix}\n{observed_at}\n{median_rssi}"
    ).encode("utf-8")


class BoardSightingRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    controller_id: str = Field(alias="controllerId", pattern=r"^[A-F0-9]{12}$")
    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    board_name: str = Field(alias="boardName", min_length=1, max_length=64)
    board_suffix: str = Field(alias="boardSuffix", pattern=r"^[A-F0-9]{6}$")
    observed_at: str = Field(alias="observedAt")
    median_rssi: str = Field(alias="medianRssi", pattern=r"^-?\d{1,3}$")
    controller_signature: str = Field(alias="controllerSignature", min_length=1, max_length=128)

    @field_validator("board_name")
    @classmethod
    def validate_board_name(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("boardName contains unsupported whitespace or control characters")
        return value

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: str) -> str:
        try:
            observed_at = _parse_iso(value)
        except ValueError as exc:
            raise ValueError("observedAt is invalid") from exc
        if observed_at.tzinfo is None:
            raise ValueError("observedAt must include a timezone")
        if abs(_now() - observed_at.astimezone(UTC)) > OBSERVATION_CLOCK_SKEW:
            raise ValueError("observedAt is outside the reporting window")
        return value

    @field_validator("median_rssi")
    @classmethod
    def validate_median_rssi(cls, value: str) -> str:
        if not -127 <= int(value) <= 20:
            raise ValueError("medianRssi is outside the supported range")
        return value


class BoardSightingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    sighting_id: str = Field(alias="sightingId")
    accepted: bool
    notification_queued: bool = Field(alias="notificationQueued")


def _active_controller_member(
    conn: sqlite3.Connection, controller_id: str, installation_id: str
):
    member = conn.execute(
        """
        SELECT m.* FROM ember_members m
        JOIN ember_installations i ON i.id = m.installation_id
        WHERE m.kind = 'controller' AND m.subject_id = ?
          AND m.installation_id = ? AND m.revoked_at IS NULL
          AND i.status = 'active'
        """,
        (controller_id, installation_id),
    ).fetchone()
    if member is None:
        raise HTTPException(status_code=403, detail="Board sighting reporter is not active.")
    return member


@router.post("/board-sightings", response_model=BoardSightingResponse)
def report_board_sighting(
    request: BoardSightingRequest, background_tasks: BackgroundTasks
) -> BoardSightingResponse:
    message = board_sighting_message(
        request.controller_id,
        request.installation_id,
        request.board_name,
        request.board_suffix,
        request.observed_at,
        request.median_rssi,
    )
    message_digest = hashlib.sha256(message).hexdigest()

    # Verify before taking SQLite's write lock, then recheck membership inside
    # the transaction so revocation cannot race an accepted sighting.
    with connect() as conn:
        controller = _active_controller_member(
            conn, request.controller_id, request.installation_id
        )
        verified_public_key = controller["public_key"]
    try:
        _verify_signature(
            controller["public_key"],
            request.controller_signature,
            message,
            "controllerSignature",
        )
    except (InvalidSignature, ValueError):
        raise HTTPException(status_code=403, detail="Board sighting signature is invalid.") from None

    now = _now()
    now_text = _iso(now)
    sighting_id = str(uuid4())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        controller = _active_controller_member(
            conn, request.controller_id, request.installation_id
        )
        if controller["public_key"] != verified_public_key:
            raise HTTPException(status_code=403, detail="Board sighting reporter changed.")
        replay = conn.execute(
            "SELECT id FROM ember_board_sightings WHERE message_digest = ?",
            (message_digest,),
        ).fetchone()
        if replay is not None:
            raise HTTPException(status_code=409, detail="Board sighting was already reported.")

        window = conn.execute(
            """
            SELECT last_queued_at FROM ember_board_notification_windows
            WHERE installation_id = ? AND board_suffix = ?
            """,
            (request.installation_id, request.board_suffix),
        ).fetchone()
        active_token = conn.execute(
            """
            SELECT 1 FROM ember_member_push_tokens t
            JOIN ember_members m ON m.id = t.member_id
            JOIN ember_installations i ON i.id = t.installation_id
            WHERE t.installation_id = ? AND t.revoked_at IS NULL
              AND m.revoked_at IS NULL AND m.kind = 'client'
              AND i.status = 'active'
            LIMIT 1
            """,
            (request.installation_id,),
        ).fetchone()
        notification_queued = (
            active_token is not None
            and (
                window is None
                or _parse_iso(window["last_queued_at"])
                <= now - NOTIFICATION_DEDUPLICATION_WINDOW
            )
        )
        conn.execute(
            """
            INSERT INTO ember_board_sightings
                (id, installation_id, controller_member_id, controller_id,
                 board_name, board_suffix, observed_at, median_rssi,
                 message_digest, received_at, notification_queued)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sighting_id,
                request.installation_id,
                controller["id"],
                request.controller_id,
                request.board_name,
                request.board_suffix,
                request.observed_at,
                int(request.median_rssi),
                message_digest,
                now_text,
                int(notification_queued),
            ),
        )
        if notification_queued:
            conn.execute(
                """
                INSERT INTO ember_board_notification_windows
                    (installation_id, board_suffix, last_queued_at, sighting_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(installation_id, board_suffix) DO UPDATE SET
                    last_queued_at = excluded.last_queued_at,
                    sighting_id = excluded.sighting_id
                """,
                (
                    request.installation_id,
                    request.board_suffix,
                    now_text,
                    sighting_id,
                ),
            )
        conn.commit()

    if notification_queued:
        background_tasks.add_task(
            dispatch_board_sighting_pushes, request.installation_id, sighting_id
        )
    return BoardSightingResponse(
        protocol=PROTOCOL,
        sightingId=sighting_id,
        accepted=True,
        notificationQueued=notification_queued,
    )
