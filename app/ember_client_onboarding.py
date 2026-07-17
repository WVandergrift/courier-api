from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db import connect
from app.ember_identity import (
    CLIENT_CAPABILITIES,
    PROTOCOL,
    _active_admin_member,
    _b64u_encode,
    _normalize_public_key,
    _parse_iso,
    _verify_signature,
    key_thumbprint,
)


JOIN_REQUEST_LIFETIME = timedelta(minutes=10)
INVITATION_LIFETIME = timedelta(seconds=60)
AUTHORIZATION_CLOCK_SKEW = timedelta(minutes=5)
router = APIRouter(prefix="/v1/ember", tags=["Ember client onboarding"])


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def client_join_approval_message(
    request_id: str,
    installation_id: str,
    candidate_key_thumbprint: str,
    approving_member_id: str,
    decision: str,
    server_nonce: str,
) -> bytes:
    return (
        "ember-client-enrollment-approval/v1\n"
        f"{request_id}\n{installation_id}\n{candidate_key_thumbprint}\n"
        f"{approving_member_id}\n{decision}\n{server_nonce}"
    ).encode("utf-8")


def client_join_list_message(
    installation_id: str, member_id: str, requested_at: str
) -> bytes:
    return (
        f"ember-client-join-list/v1\n{installation_id}\n{member_id}\n{requested_at}"
    ).encode("utf-8")


def client_invitation_message(
    invitation_id: str,
    installation_id: str,
    authorizer_member_id: str,
    secret_hash: str,
    server_nonce: str,
    expires_at: str,
) -> bytes:
    return (
        "ember-client-invitation/v1\n"
        f"{invitation_id}\n{installation_id}\n{authorizer_member_id}\n"
        f"{secret_hash}\n{server_nonce}\n{expires_at}"
    ).encode("utf-8")


class JoinRequestCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    controller_id: str = Field(alias="controllerId", pattern=r"^[A-F0-9]{12}$")
    client_public_key: str = Field(alias="clientPublicKey")
    client_name: str = Field(alias="clientName", min_length=1, max_length=64)

    @field_validator("client_public_key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return _normalize_public_key(value)

    @field_validator("client_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return " ".join(value.split())


class JoinRequestDecision(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    approving_member_id: str = Field(alias="approvingMemberId", min_length=1, max_length=64)
    decision: Literal["approve", "deny"]
    client_signature: str = Field(alias="clientSignature")


class JoinListRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    member_id: str = Field(alias="memberId", min_length=1, max_length=64)
    requested_at: str = Field(alias="requestedAt")
    client_signature: str = Field(alias="clientSignature")


class InvitationCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    installation_id: str = Field(alias="installationId", min_length=1, max_length=64)
    authorizer_member_id: str = Field(alias="authorizerMemberId", min_length=1, max_length=64)


class InvitationAuthorize(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    client_signature: str = Field(alias="clientSignature")


class InvitationRedeem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    secret: str = Field(min_length=32, max_length=128)
    client_public_key: str = Field(alias="clientPublicKey")
    client_name: str = Field(alias="clientName", min_length=1, max_length=64)

    @field_validator("client_public_key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return _normalize_public_key(value)

    @field_validator("client_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return " ".join(value.split())


def _controller_installation(conn: sqlite3.Connection, controller_id: str):
    row = conn.execute(
        """
        SELECT m.installation_id, m.id AS controller_member_id, m.display_name
        FROM ember_members m
        JOIN ember_installations i ON i.id = m.installation_id
        WHERE m.kind = 'controller' AND m.subject_id = ?
          AND m.revoked_at IS NULL AND i.status = 'active'
        """,
        (controller_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="This controller is not available for Home access.")
    return row


def _membership_payload(installation_id: str, member_id: str, controller_member_id: str):
    return {
        "protocol": PROTOCOL,
        "installationId": installation_id,
        "memberId": member_id,
        "controllerMemberId": controller_member_id,
        "createdInstallation": False,
    }


def _insert_client_member(
    conn: sqlite3.Connection,
    installation_id: str,
    public_key: str,
    display_name: str,
    now: str,
) -> str:
    thumbprint = key_thumbprint(public_key)
    existing = conn.execute(
        """SELECT id FROM ember_members
           WHERE installation_id = ? AND kind = 'client' AND key_thumbprint = ?""",
        (installation_id, thumbprint),
    ).fetchone()
    if existing:
        return existing["id"]
    member_id = str(uuid4())
    conn.execute(
        """
        INSERT INTO ember_members
            (id, installation_id, kind, subject_id, public_key, key_thumbprint,
             display_name, capabilities_json, created_at, updated_at)
        VALUES (?, ?, 'client', ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            member_id, installation_id, f"client:{thumbprint[:16]}", public_key,
            thumbprint, display_name, json.dumps(CLIENT_CAPABILITIES), now, now,
        ),
    )
    return member_id


@router.post("/client-join-requests")
def create_join_request(request: JoinRequestCreate):
    now = _now()
    thumbprint = key_thumbprint(request.client_public_key)
    with connect() as conn:
        controller = _controller_installation(conn, request.controller_id)
        existing_member = conn.execute(
            """SELECT id FROM ember_members
               WHERE installation_id = ? AND kind = 'client' AND key_thumbprint = ?""",
            (controller["installation_id"], thumbprint),
        ).fetchone()
        if existing_member:
            return {
                "requestId": "",
                "status": "approved",
                "expiresAt": _iso(now),
                **_membership_payload(
                    controller["installation_id"], existing_member["id"],
                    controller["controller_member_id"],
                ),
            }
        existing = conn.execute(
            """
            SELECT * FROM ember_join_requests
            WHERE installation_id = ? AND candidate_key_thumbprint = ?
              AND status = 'pending' AND expires_at > ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (controller["installation_id"], thumbprint, _iso(now)),
        ).fetchone()
        if existing:
            return _join_payload(existing, controller["controller_member_id"])
        request_id = str(uuid4())
        expires_at = _iso(now + JOIN_REQUEST_LIFETIME)
        conn.execute(
            """
            INSERT INTO ember_join_requests
                (id, installation_id, controller_id, candidate_public_key,
                 candidate_key_thumbprint, candidate_name, server_nonce,
                 created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id, controller["installation_id"], request.controller_id,
                request.client_public_key, thumbprint, request.client_name,
                _b64u_encode(secrets.token_bytes(32)), _iso(now), expires_at,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM ember_join_requests WHERE id = ?", (request_id,)).fetchone()
        return _join_payload(row, controller["controller_member_id"])


def _join_payload(row, controller_member_id: str | None = None):
    payload = {
        "protocol": PROTOCOL,
        "requestId": row["id"],
        "installationId": row["installation_id"],
        "controllerId": row["controller_id"],
        "clientName": row["candidate_name"],
        "candidateKeyThumbprint": row["candidate_key_thumbprint"],
        "serverNonce": row["server_nonce"],
        "status": row["status"],
        "createdAt": row["created_at"],
        "expiresAt": row["expires_at"],
    }
    if row["member_id"]:
        if controller_member_id is None:
            with connect() as conn:
                controller_member_id = _controller_installation(conn, row["controller_id"])["controller_member_id"]
        payload.update(_membership_payload(row["installation_id"], row["member_id"], controller_member_id))
    return payload


@router.get("/client-join-requests/{request_id}")
def get_join_request(
    request_id: str,
    client_public_key: str = Query(alias="clientPublicKey"),
):
    try:
        thumbprint = key_thumbprint(_normalize_public_key(client_public_key))
    except ValueError:
        raise HTTPException(status_code=422, detail="Client public key is invalid.") from None
    with connect() as conn:
        row = conn.execute("SELECT * FROM ember_join_requests WHERE id = ?", (request_id,)).fetchone()
    if not row or not hmac.compare_digest(row["candidate_key_thumbprint"], thumbprint):
        raise HTTPException(status_code=404, detail="Home access request was not found.")
    return _join_payload(row)


@router.post("/client-join-requests/pending")
def list_pending_join_requests(request: JoinListRequest):
    try:
        requested_at = _parse_iso(request.requested_at)
    except ValueError:
        raise HTTPException(status_code=422, detail="requestedAt is invalid.") from None
    if abs(_now() - requested_at) > AUTHORIZATION_CLOCK_SKEW:
        raise HTTPException(status_code=422, detail="Join request authorization is stale.")
    with connect() as conn:
        member = _active_admin_member(conn, request.installation_id, request.member_id)
        try:
            _verify_signature(
                member["public_key"], request.client_signature,
                client_join_list_message(request.installation_id, request.member_id, request.requested_at),
                "clientSignature",
            )
        except (ValueError, InvalidSignature):
            raise HTTPException(status_code=403, detail="Join request authorization is invalid.") from None
        rows = conn.execute(
            """
            SELECT * FROM ember_join_requests
            WHERE installation_id = ? AND status = 'pending' AND expires_at > ?
            ORDER BY created_at ASC
            """,
            (request.installation_id, _iso(_now())),
        ).fetchall()
    return {"protocol": PROTOCOL, "requests": [_join_payload(row) for row in rows]}


@router.post("/client-join-requests/{request_id}/decision")
def decide_join_request(request_id: str, request: JoinRequestDecision):
    with connect() as conn:
        row = conn.execute("SELECT * FROM ember_join_requests WHERE id = ?", (request_id,)).fetchone()
        if not row or row["installation_id"] != request.installation_id:
            raise HTTPException(status_code=404, detail="Home access request was not found.")
        member = _active_admin_member(conn, request.installation_id, request.approving_member_id)
    if row["status"] != "pending":
        raise HTTPException(status_code=409, detail="Home access request was already decided.")
    if _parse_iso(row["expires_at"]) <= _now():
        raise HTTPException(status_code=410, detail="Home access request expired.")
    try:
        _verify_signature(
            member["public_key"], request.client_signature,
            client_join_approval_message(
                row["id"], row["installation_id"], row["candidate_key_thumbprint"],
                request.approving_member_id, request.decision, row["server_nonce"],
            ),
            "clientSignature",
        )
    except (ValueError, InvalidSignature):
        raise HTTPException(status_code=403, detail="Home access decision signature is invalid.") from None

    now = _iso(_now())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute("SELECT * FROM ember_join_requests WHERE id = ?", (request_id,)).fetchone()
        if not current or current["status"] != "pending":
            raise HTTPException(status_code=409, detail="Home access request was already decided.")
        _active_admin_member(conn, request.installation_id, request.approving_member_id)
        member_id = None
        if request.decision == "approve":
            member_id = _insert_client_member(
                conn, current["installation_id"], current["candidate_public_key"],
                current["candidate_name"], now,
            )
        conn.execute(
            """UPDATE ember_join_requests
               SET status = ?, decided_at = ?, approving_member_id = ?, member_id = ?
               WHERE id = ?""",
            ("approved" if member_id else "denied", now, request.approving_member_id, member_id, request_id),
        )
        conn.execute(
            """INSERT INTO ember_audit_events
               (installation_id, actor_member_id, event_type, subject_id, detail_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                request.installation_id, request.approving_member_id,
                "client_join_approved" if member_id else "client_join_denied",
                member_id or request_id,
                json.dumps({"requestId": request_id}, sort_keys=True), now,
            ),
        )
        conn.commit()
        decided = conn.execute("SELECT * FROM ember_join_requests WHERE id = ?", (request_id,)).fetchone()
    return _join_payload(decided)


@router.post("/client-invitations")
def create_invitation(request: InvitationCreate):
    now = _now()
    invitation_id = str(uuid4())
    secret = _b64u_encode(secrets.token_bytes(32))
    with connect() as conn:
        _active_admin_member(conn, request.installation_id, request.authorizer_member_id)
        conn.execute(
            """
            INSERT INTO ember_client_invitations
                (id, installation_id, authorizer_member_id, secret_hash,
                 server_nonce, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                invitation_id, request.installation_id, request.authorizer_member_id,
                hashlib.sha256(secret.encode()).hexdigest(),
                _b64u_encode(secrets.token_bytes(32)), _iso(now),
                _iso(now + INVITATION_LIFETIME),
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM ember_client_invitations WHERE id = ?", (invitation_id,)).fetchone()
    return _invitation_payload(row, secret)


def _invitation_payload(row, secret: str | None = None):
    payload = {
        "protocol": PROTOCOL,
        "invitationId": row["id"],
        "installationId": row["installation_id"],
        "authorizerMemberId": row["authorizer_member_id"],
        "secretHash": row["secret_hash"],
        "serverNonce": row["server_nonce"],
        "expiresAt": row["expires_at"],
        "authorized": bool(row["authorized_at"]),
        "consumed": bool(row["consumed_at"]),
    }
    if secret is not None:
        payload["secret"] = secret
    return payload


@router.post("/client-invitations/{invitation_id}/authorize")
def authorize_invitation(invitation_id: str, request: InvitationAuthorize):
    with connect() as conn:
        row = conn.execute("SELECT * FROM ember_client_invitations WHERE id = ?", (invitation_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Home invitation was not found.")
        member = _active_admin_member(conn, row["installation_id"], row["authorizer_member_id"])
    if row["authorized_at"] or row["consumed_at"]:
        raise HTTPException(status_code=409, detail="Home invitation was already used.")
    if _parse_iso(row["expires_at"]) <= _now():
        raise HTTPException(status_code=410, detail="Home invitation expired.")
    try:
        _verify_signature(
            member["public_key"], request.client_signature,
            client_invitation_message(
                row["id"], row["installation_id"], row["authorizer_member_id"],
                row["secret_hash"], row["server_nonce"], row["expires_at"],
            ),
            "clientSignature",
        )
    except (ValueError, InvalidSignature):
        raise HTTPException(status_code=403, detail="Home invitation signature is invalid.") from None
    with connect() as conn:
        result = conn.execute(
            """UPDATE ember_client_invitations SET authorized_at = ?
               WHERE id = ? AND authorized_at IS NULL AND consumed_at IS NULL""",
            (_iso(_now()), invitation_id),
        )
        if result.rowcount != 1:
            raise HTTPException(status_code=409, detail="Home invitation was already used.")
        conn.commit()
        authorized = conn.execute("SELECT * FROM ember_client_invitations WHERE id = ?", (invitation_id,)).fetchone()
    return _invitation_payload(authorized)


@router.post("/client-invitations/{invitation_id}/redeem")
def redeem_invitation(invitation_id: str, request: InvitationRedeem):
    secret_hash = hashlib.sha256(request.secret.encode()).hexdigest()
    now = _iso(_now())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM ember_client_invitations WHERE id = ?", (invitation_id,)).fetchone()
        if not row or not hmac.compare_digest(row["secret_hash"], secret_hash):
            raise HTTPException(status_code=404, detail="Home invitation was not found.")
        if not row["authorized_at"]:
            raise HTTPException(status_code=403, detail="Home invitation is not approved.")
        if row["consumed_at"]:
            raise HTTPException(status_code=409, detail="Home invitation was already used.")
        if _parse_iso(row["expires_at"]) <= _now():
            raise HTTPException(status_code=410, detail="Home invitation expired.")
        _active_admin_member(conn, row["installation_id"], row["authorizer_member_id"])
        member_id = _insert_client_member(
            conn, row["installation_id"], request.client_public_key, request.client_name, now,
        )
        controller = conn.execute(
            """SELECT id FROM ember_members
               WHERE installation_id = ? AND kind = 'controller' AND revoked_at IS NULL
               ORDER BY created_at LIMIT 1""",
            (row["installation_id"],),
        ).fetchone()
        if not controller:
            raise HTTPException(status_code=409, detail="Home has no active controller.")
        conn.execute(
            "UPDATE ember_client_invitations SET consumed_at = ?, member_id = ? WHERE id = ?",
            (now, member_id, invitation_id),
        )
        conn.execute(
            """INSERT INTO ember_audit_events
               (installation_id, actor_member_id, event_type, subject_id, detail_json, created_at)
               VALUES (?, ?, 'client_invitation_redeemed', ?, ?, ?)""",
            (
                row["installation_id"], row["authorizer_member_id"], member_id,
                json.dumps({"invitationId": invitation_id}, sort_keys=True), now,
            ),
        )
        conn.commit()
    return _membership_payload(row["installation_id"], member_id, controller["id"])
