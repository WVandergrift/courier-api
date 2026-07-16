from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth import require_auth


router = APIRouter(prefix="/v1/diagnostics/oelo", tags=["oelo-diagnostics"])

MAX_ACTIVE_SESSIONS = 16
MAX_SESSION_SECONDS = 3600
MAX_BUFFERED_LINES = 512
MAX_BATCH_LINES = 64
MAX_LINE_BYTES = 512
MAX_BODY_BYTES = 16 * 1024
MAX_POSTS_PER_SECOND = 10


def _clock() -> float:
    return time.time()


def _iso_time(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")


def _token_digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _bearer_token(value: str | None) -> str:
    if not value:
        return ""
    try:
        scheme, token = value.split(" ", 1)
    except ValueError:
        return ""
    return token.strip() if scheme.lower() == "bearer" else ""


class DiagnosticSessionRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    hardware_id: str = Field(alias="hardwareId", pattern=r"^[A-Fa-f0-9]{12}$")
    ttl_seconds: int = Field(default=600, alias="ttlSeconds", ge=30, le=MAX_SESSION_SECONDS)

    @field_validator("hardware_id")
    @classmethod
    def normalize_hardware_id(cls, value: str) -> str:
        return value.upper()


class DiagnosticSessionResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    hardware_id: str = Field(alias="hardwareId")
    ingest_token: str = Field(alias="ingestToken")
    expires_at: str = Field(alias="expiresAt")
    ingest_path: str = Field(alias="ingestPath")
    tail_path: str = Field(alias="tailPath")


class DiagnosticIngestResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    accepted: int
    next_cursor: int = Field(alias="nextCursor")


class DiagnosticLine(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cursor: int
    received_at: str = Field(alias="receivedAt")
    text: str


class DiagnosticTailResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    hardware_id: str = Field(alias="hardwareId")
    expires_at: str = Field(alias="expiresAt")
    next_cursor: int = Field(alias="nextCursor")
    lines: list[DiagnosticLine]


@dataclass(frozen=True)
class _BufferedLine:
    cursor: int
    received_at: float
    text: str


@dataclass
class _DiagnosticSession:
    id: str
    hardware_id: str
    token_digest: bytes
    created_at: float
    expires_at: float
    next_cursor: int = 1
    lines: deque[_BufferedLine] = field(default_factory=lambda: deque(maxlen=MAX_BUFFERED_LINES))
    recent_posts: deque[float] = field(default_factory=deque)


_lock = RLock()
_sessions: dict[str, _DiagnosticSession] = {}


def _purge_expired(now: float) -> None:
    expired = [session_id for session_id, session in _sessions.items() if session.expires_at <= now]
    for session_id in expired:
        del _sessions[session_id]


def _active_session(session_id: str, now: float) -> _DiagnosticSession:
    _purge_expired(now)
    session = _sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Diagnostic session was not found or has expired.")
    return session


@router.post(
    "/sessions",
    response_model=DiagnosticSessionResponse,
    dependencies=[Depends(require_auth)],
)
def create_diagnostic_session(request: DiagnosticSessionRequest, response: Response) -> DiagnosticSessionResponse:
    now = _clock()
    token = secrets.token_urlsafe(32)
    session_id = str(uuid4())
    with _lock:
        _purge_expired(now)
        if len(_sessions) >= MAX_ACTIVE_SESSIONS:
            raise HTTPException(status_code=503, detail="Too many active diagnostic sessions.")
        session = _DiagnosticSession(
            id=session_id,
            hardware_id=request.hardware_id,
            token_digest=_token_digest(token),
            created_at=now,
            expires_at=now + request.ttl_seconds,
        )
        _sessions[session_id] = session

    response.headers["Cache-Control"] = "no-store"
    ingest_path = f"/v1/diagnostics/oelo/sessions/{session_id}/logs"
    return DiagnosticSessionResponse(
        sessionId=session_id,
        hardwareId=session.hardware_id,
        ingestToken=token,
        expiresAt=_iso_time(session.expires_at),
        ingestPath=ingest_path,
        tailPath=f"/v1/diagnostics/oelo/sessions/{session_id}/tail",
    )


@router.post("/sessions/{session_id}/logs", response_model=DiagnosticIngestResponse)
async def ingest_diagnostic_lines(
    session_id: str,
    request: Request,
    response: Response,
    authorization: str | None = Header(default=None),
) -> DiagnosticIngestResponse:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="Content-Length is invalid.") from None
        if declared_length > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Diagnostic batch is too large.")

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Diagnostic batch is empty.")
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Diagnostic batch is too large.")

    now = _clock()
    with _lock:
        session = _active_session(session_id, now)
        provided = _bearer_token(authorization)
        if not provided or not hmac.compare_digest(_token_digest(provided), session.token_digest):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

        while session.recent_posts and session.recent_posts[0] <= now - 1:
            session.recent_posts.popleft()
        if len(session.recent_posts) >= MAX_POSTS_PER_SECOND:
            raise HTTPException(status_code=429, detail="Diagnostic ingest rate exceeded.")

        raw_lines = body.decode("utf-8", errors="replace").splitlines()
        if not raw_lines:
            raw_lines = [body.decode("utf-8", errors="replace")]
        if len(raw_lines) > MAX_BATCH_LINES:
            raise HTTPException(status_code=413, detail="Diagnostic batch contains too many lines.")

        session.recent_posts.append(now)
        accepted = 0
        for raw_line in raw_lines:
            line = raw_line.encode("utf-8")[:MAX_LINE_BYTES].decode("utf-8", errors="ignore")
            session.lines.append(_BufferedLine(session.next_cursor, now, line))
            session.next_cursor += 1
            accepted += 1

        response.headers["Cache-Control"] = "no-store"
        return DiagnosticIngestResponse(accepted=accepted, nextCursor=session.next_cursor - 1)


@router.get(
    "/sessions/{session_id}/tail",
    response_model=DiagnosticTailResponse,
    dependencies=[Depends(require_auth)],
)
def tail_diagnostic_session(
    session_id: str,
    response: Response,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=200),
) -> DiagnosticTailResponse:
    now = _clock()
    with _lock:
        session = _active_session(session_id, now)
        buffered = [line for line in session.lines if line.cursor > after][:limit]
        next_cursor = buffered[-1].cursor if buffered else after
        response.headers["Cache-Control"] = "no-store"
        return DiagnosticTailResponse(
            sessionId=session.id,
            hardwareId=session.hardware_id,
            expiresAt=_iso_time(session.expires_at),
            nextCursor=next_cursor,
            lines=[
                DiagnosticLine(cursor=line.cursor, receivedAt=_iso_time(line.received_at), text=line.text)
                for line in buffered
            ],
        )


@router.delete(
    "/sessions/{session_id}",
    status_code=204,
    dependencies=[Depends(require_auth)],
)
def delete_diagnostic_session(session_id: str) -> Response:
    with _lock:
        if _sessions.pop(session_id, None) is None:
            raise HTTPException(status_code=404, detail="Diagnostic session was not found.")
    return Response(status_code=204)
