from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.exceptions import InvalidSignature
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db import connect
from app.ember_identity import _active_admin_member, _b64u_decode, _verify_signature


PROTOCOL = "ember-installation-document-v1"
REQUEST_WINDOW = timedelta(minutes=5)
MAX_DOCUMENT_BYTES = 12 * 1024 * 1024
MAX_INSTALLATION_DOCUMENT_BYTES = 128 * 1024 * 1024
DOCUMENT_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$")
CONTENT_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")

router = APIRouter(prefix="/v1/ember/installation-documents", tags=["Ember installation documents"])


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


def installation_document_message(
    action: Literal["read", "write", "delete"],
    installation_id: str,
    member_id: str,
    document_key: str,
    expected_revision: int,
    payload_digest: str,
    content_type: str,
    requested_at: str,
) -> bytes:
    return (
        f"{PROTOCOL}\n{action}\n{installation_id}\n{member_id}\n{document_key}\n"
        f"{expected_revision}\n{payload_digest}\n{content_type}\n{requested_at}"
    ).encode("utf-8")


def _validate_document_key(value: str) -> str:
    if not DOCUMENT_KEY_PATTERN.fullmatch(value) or "//" in value or "/../" in f"/{value}/":
        raise ValueError("document key is invalid")
    return value


class DocumentAuthorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    member_id: str = Field(alias="memberId", min_length=1, max_length=64)
    requested_at: str = Field(alias="requestedAt")
    client_signature: str = Field(alias="clientSignature")

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


class DocumentRead(DocumentAuthorization):
    pass


class DocumentWrite(DocumentAuthorization):
    expected_revision: int = Field(alias="expectedRevision", ge=0)
    content_type: str = Field(alias="contentType", min_length=3, max_length=96)
    payload: str = Field(max_length=17_000_000)
    payload_digest: str = Field(alias="payloadDigest", pattern=r"^[a-f0-9]{64}$")

    @field_validator("content_type")
    @classmethod
    def validate_content_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not CONTENT_TYPE_PATTERN.fullmatch(normalized):
            raise ValueError("contentType is invalid")
        return normalized


class DocumentDelete(DocumentAuthorization):
    expected_revision: int = Field(alias="expectedRevision", ge=1)


class InstallationDocumentResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str = PROTOCOL
    document_key: str = Field(alias="documentKey")
    revision: int
    installation_revision: int = Field(alias="installationRevision")
    content_type: str = Field(alias="contentType")
    payload: str | None = None
    payload_digest: str = Field(alias="payloadDigest")
    updated_at: str = Field(alias="updatedAt")


class InstallationDocumentDeleteResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: str = PROTOCOL
    document_key: str = Field(alias="documentKey")
    deleted: bool
    installation_revision: int = Field(alias="installationRevision")


def _decode_payload(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Document payload is not valid base64url.") from exc
    if len(decoded) > MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=413, detail="Installation document is too large.")
    return decoded


def _authorize(
    conn: sqlite3.Connection,
    request: DocumentAuthorization,
    action: Literal["read", "write", "delete"],
    document_key: str,
    expected_revision: int,
    payload_digest: str,
    content_type: str,
):
    member = _active_admin_member(conn, request.installation_id, request.member_id)
    try:
        _verify_signature(
            member["public_key"],
            request.client_signature,
            installation_document_message(
                action,
                request.installation_id,
                request.member_id,
                document_key,
                expected_revision,
                payload_digest,
                content_type,
                request.requested_at,
            ),
            "clientSignature",
        )
    except (InvalidSignature, ValueError):
        raise HTTPException(status_code=403, detail="Installation document authorization is invalid.") from None
    return member


def _installation_revision(conn: sqlite3.Connection, installation_id: str) -> int:
    row = conn.execute("SELECT revision FROM ember_installations WHERE id = ?", (installation_id,)).fetchone()
    return int(row["revision"])


def _response(conn: sqlite3.Connection, row, *, include_payload: bool) -> InstallationDocumentResponse:
    payload = bytes(row["payload"])
    return InstallationDocumentResponse(
        documentKey=row["document_key"],
        revision=row["revision"],
        installationRevision=_installation_revision(conn, row["installation_id"]),
        contentType=row["content_type"],
        payload=base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=") if include_payload else None,
        payloadDigest=row["payload_digest"],
        updatedAt=row["updated_at"],
    )


@router.post("/{document_key:path}", response_model=InstallationDocumentResponse)
def read_installation_document(document_key: str, request: DocumentRead) -> InstallationDocumentResponse:
    document_key = _validate_document_key(document_key)
    with connect() as conn:
        _authorize(conn, request, "read", document_key, 0, "-", "-")
        row = conn.execute(
            "SELECT * FROM ember_installation_documents WHERE installation_id = ? AND document_key = ?",
            (request.installation_id, document_key),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Installation document was not found.")
        return _response(conn, row, include_payload=True)


@router.put("/{document_key:path}", response_model=InstallationDocumentResponse)
def write_installation_document(document_key: str, request: DocumentWrite) -> InstallationDocumentResponse:
    document_key = _validate_document_key(document_key)
    payload = _decode_payload(request.payload)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != request.payload_digest:
        raise HTTPException(status_code=400, detail="Document payload digest does not match.")
    now = _iso(_now())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        member = _authorize(
            conn, request, "write", document_key, request.expected_revision,
            request.payload_digest, request.content_type,
        )
        current = conn.execute(
            "SELECT * FROM ember_installation_documents WHERE installation_id = ? AND document_key = ?",
            (request.installation_id, document_key),
        ).fetchone()
        current_revision = int(current["revision"]) if current else 0
        if current_revision != request.expected_revision:
            raise HTTPException(
                status_code=409,
                detail=f"Installation document changed (current revision {current_revision}).",
            )
        current_size = len(current["payload"]) if current else 0
        total_size = conn.execute(
            "SELECT COALESCE(SUM(length(payload)), 0) AS bytes FROM ember_installation_documents WHERE installation_id = ?",
            (request.installation_id,),
        ).fetchone()["bytes"]
        if int(total_size) - current_size + len(payload) > MAX_INSTALLATION_DOCUMENT_BYTES:
            raise HTTPException(status_code=413, detail="Installation document storage limit was reached.")
        revision = current_revision + 1
        conn.execute(
            """
            INSERT INTO ember_installation_documents
                (installation_id, document_key, revision, content_type, payload,
                 payload_digest, updated_by_member_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(installation_id, document_key) DO UPDATE SET
                revision = excluded.revision,
                content_type = excluded.content_type,
                payload = excluded.payload,
                payload_digest = excluded.payload_digest,
                updated_by_member_id = excluded.updated_by_member_id,
                updated_at = excluded.updated_at
            """,
            (
                request.installation_id, document_key, revision, request.content_type,
                payload, digest, member["id"], now, now,
            ),
        )
        conn.execute(
            "UPDATE ember_installations SET revision = revision + 1, updated_at = ? WHERE id = ?",
            (now, request.installation_id),
        )
        conn.execute(
            """
            INSERT INTO ember_audit_events
                (installation_id, actor_member_id, event_type, subject_id, detail_json, created_at)
            VALUES (?, ?, 'installation_document_written', ?, ?, ?)
            """,
            (
                request.installation_id, member["id"], document_key,
                json.dumps({"revision": revision, "payloadDigest": digest, "contentType": request.content_type}, separators=(",", ":")),
                now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM ember_installation_documents WHERE installation_id = ? AND document_key = ?",
            (request.installation_id, document_key),
        ).fetchone()
        conn.commit()
        return _response(conn, row, include_payload=False)


@router.delete("/{document_key:path}", response_model=InstallationDocumentDeleteResponse)
def delete_installation_document(document_key: str, request: DocumentDelete) -> InstallationDocumentDeleteResponse:
    document_key = _validate_document_key(document_key)
    now = _iso(_now())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        member = _authorize(conn, request, "delete", document_key, request.expected_revision, "-", "-")
        current = conn.execute(
            "SELECT revision FROM ember_installation_documents WHERE installation_id = ? AND document_key = ?",
            (request.installation_id, document_key),
        ).fetchone()
        current_revision = int(current["revision"]) if current else 0
        if current_revision != request.expected_revision:
            raise HTTPException(
                status_code=409,
                detail=f"Installation document changed (current revision {current_revision}).",
            )
        conn.execute(
            "DELETE FROM ember_installation_documents WHERE installation_id = ? AND document_key = ?",
            (request.installation_id, document_key),
        )
        conn.execute(
            "UPDATE ember_installations SET revision = revision + 1, updated_at = ? WHERE id = ?",
            (now, request.installation_id),
        )
        conn.execute(
            """
            INSERT INTO ember_audit_events
                (installation_id, actor_member_id, event_type, subject_id, detail_json, created_at)
            VALUES (?, ?, 'installation_document_deleted', ?, '{}', ?)
            """,
            (request.installation_id, member["id"], document_key, now),
        )
        conn.commit()
        return InstallationDocumentDeleteResponse(
            documentKey=document_key,
            deleted=True,
            installationRevision=_installation_revision(conn, request.installation_id),
        )
