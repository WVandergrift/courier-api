"""Companion relay: a blind tunnel between the mobile app and a Pulse daemon
that sits behind NAT.

The daemon opens an authenticated **outbound** WebSocket to Courier and
registers under its Ed25519 signing-key id (proving possession by signing the
registration). The mobile app, when off-LAN, POSTs a request addressed to that
key id; Courier forwards it down the daemon's socket and returns the reply.

Courier never inspects or trusts the payload — every request is Ed25519-signed
by the app and every response is signed by the daemon (companion auth v2), so a
compromised or curious relay can neither forge nor read traffic. Courier only:
  * proves, at registration, that a socket owns the key id it claims, and
  * routes request/response frames by that id.

Protocol (JSON frames):
  daemon -> courier (first frame):
    {"type":"register","keyId":<b64u ed pub>,"ts":<ms>,
     "sig":<b64u ed25519 over "pulse-relay-register/v1\\n<keyId>\\n<ts>">}
  courier -> daemon: {"type":"registered"}  |  close(4001) on bad register
  courier -> daemon: {"type":"request","id":<uuid>,"method","path","headers","body"}
  daemon -> courier: {"type":"response","id":<uuid>,"status","headers","body"}
  daemon <-> courier keepalive: {"type":"ping"} / {"type":"pong"}

  app -> courier:  POST /v1/relay/{keyId}/req  {method,path,headers,body}
                   -> 200 {status,headers,body} | 502 offline | 504 timeout

Live streams (Pulse stream protocol v1, tools/pulse-daemon/docs/stream-protocol.md):
  app -> courier:  WebSocket /v1/relay/{keyId}/stream, opaque text frames
  courier -> daemon: {"type":"stream.open","sid"}
  courier <-> daemon: {"type":"stream.data","sid","data"}  one app text frame
  courier <-> daemon: {"type":"stream.close","sid","code","reason"}
  Close codes Courier sends: 4404 daemon not connected, 4429 more than 8
  streams, 4408 idle 5 min, 1009 frame > 64 KiB, 1003 binary frame,
  1013 app not reading, 1001 daemon re-registered, 1011 relay error.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.logging_config import log_fields

logger = logging.getLogger("courier.relay")

REGISTER_SKEW_MS = 5 * 60 * 1000
FORWARD_TIMEOUT_S = 20.0
# Only these path prefixes may be relayed to a daemon — the companion API and
# the unpair route. Keeps the tunnel from being used to probe other surfaces.
ALLOWED_PREFIXES = ("/v1/companion/", "/client")

STREAM_MAX_FRAME_BYTES = 64 * 1024
STREAM_OUTBOX_MAX = 32
STREAM_MAX_PER_DAEMON = 8
STREAM_IDLE_S = 5 * 60.0


def _b64u_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def verify_register(frame: dict[str, Any], now_ms: int | None = None) -> str | None:
    """Return the validated key id if the register frame proves ownership, else None."""
    if not isinstance(frame, dict) or frame.get("type") != "register":
        return None
    key_id = frame.get("keyId")
    ts = frame.get("ts")
    sig = frame.get("sig")
    if not isinstance(key_id, str) or not isinstance(sig, str) or not isinstance(ts, (int, float)):
        return None
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    if abs(now - int(ts)) > REGISTER_SKEW_MS:
        return None
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64u_decode(key_id))
        message = f"pulse-relay-register/v1\n{key_id}\n{int(ts)}".encode("utf-8")
        pub.verify(_b64u_decode(sig), message)
    except (InvalidSignature, ValueError, Exception):  # noqa: BLE001 - any failure = reject
        return None
    return key_id


class RelayHub:
    """Registry of connected daemons (keyId -> WebSocket) and the in-flight
    request futures awaiting a response frame."""

    def __init__(self) -> None:
        self._agents: dict[str, WebSocket] = {}
        self._pending: dict[str, asyncio.Future] = {}
        # Streams are keyed by the agent socket, not the key id, so a daemon that
        # re-registers can never receive or address its predecessor's streams.
        self._streams: dict[WebSocket, dict[str, _Stream]] = {}

    def agent_count(self) -> int:
        return len(self._agents)

    def is_online(self, key_id: str) -> bool:
        return key_id in self._agents

    def register(self, key_id: str, ws: WebSocket) -> WebSocket | None:
        """Register (or replace) the socket for a key id. Returns any socket it
        displaced so the caller can close it (one active tunnel per daemon)."""
        old = self._agents.get(key_id)
        self._agents[key_id] = ws
        return old if old is not ws else None

    def unregister(self, key_id: str, ws: WebSocket) -> None:
        # Only remove if the current socket is the one disconnecting (a newer
        # tunnel may have already replaced it).
        if self._agents.get(key_id) is ws:
            del self._agents[key_id]

    def resolve(self, request_id: str, frame: dict[str, Any]) -> None:
        fut = self._pending.get(request_id)
        if fut is not None and not fut.done():
            fut.set_result(frame)

    def fail_pending_for(self, ws: WebSocket) -> None:
        # Called on disconnect — nothing tracks per-socket futures, so the
        # timeout is the backstop. Kept for symmetry / future per-socket maps.
        return None

    async def forward(self, key_id: str, request: dict[str, Any]) -> dict[str, Any]:
        ws = self._agents.get(key_id)
        if ws is None:
            raise HTTPException(status_code=502, detail="daemon is not connected")
        request_id = uuid4().hex
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[request_id] = fut
        try:
            await ws.send_json({"type": "request", "id": request_id, **request})
            return await asyncio.wait_for(fut, timeout=FORWARD_TIMEOUT_S)
        except asyncio.TimeoutError as exc:
            raise HTTPException(status_code=504, detail="daemon did not respond in time") from exc
        finally:
            self._pending.pop(request_id, None)

    def open_stream(self, key_id: str, phone: WebSocket) -> _Stream | int:
        """Allocate a stream on the daemon's current agent socket, or return the
        close code that rejects it."""
        agent = self._agents.get(key_id)
        if agent is None:
            return 4404
        streams = self._streams.setdefault(agent, {})
        if len(streams) >= STREAM_MAX_PER_DAEMON:
            return 4429
        stream = _Stream(uuid4().hex, key_id, phone, agent)
        streams[stream.sid] = stream
        return stream

    def _stream_on(self, agent: WebSocket, sid: str) -> _Stream | None:
        return self._streams.get(agent, {}).get(sid)

    def stream_data_from_agent(self, agent: WebSocket, sid: str, data: str) -> None:
        stream = self._stream_on(agent, sid)
        if stream is None or stream.ended.done():
            return
        if len(data.encode("utf-8")) > STREAM_MAX_FRAME_BYTES:
            stream.end(1009, "frame too large", notify_agent=True)
            return
        if stream.outbox.qsize() >= STREAM_OUTBOX_MAX:
            stream.end(1013, "phone is not reading", notify_agent=True)
            return
        stream.touch()
        stream.outbox.put_nowait(("data", data))

    def stream_close_from_agent(self, agent: WebSocket, sid: str, code: Any, reason: Any) -> None:
        stream = self._stream_on(agent, sid)
        if stream is None or stream.ended.done():
            return
        stream.outbox.put_nowait(("close", (_close_code(code), _close_reason(reason))))

    def end_streams_for(self, agent: WebSocket, code: int, reason: str) -> None:
        """End every stream on an agent socket that is going away. The daemon
        is not told: its socket is gone or has been replaced."""
        for stream in self._streams.pop(agent, {}).values():
            stream.end(code, reason, notify_agent=False)

    def remove_stream(self, stream: _Stream) -> None:
        streams = self._streams.get(stream.agent)
        if streams is not None and streams.get(stream.sid) is stream:
            del streams[stream.sid]
            if not streams:
                del self._streams[stream.agent]


def _close_code(code: Any) -> int:
    """A code we may send in a close frame; anything else becomes 1000."""
    if isinstance(code, int) and not isinstance(code, bool) and (code == 1000 or 3000 <= code <= 4999):
        return code
    return 1000


def _close_reason(reason: Any) -> str:
    # A close frame's reason is limited to 123 UTF-8 bytes.
    if not isinstance(reason, str):
        return ""
    return reason.encode("utf-8")[:123].decode("utf-8", errors="ignore")


class _Stream:
    """One phone WebSocket multiplexed onto a daemon's agent socket."""

    def __init__(self, sid: str, key_id: str, phone: WebSocket, agent: WebSocket) -> None:
        self.sid = sid
        self.key_id = key_id
        self.phone = phone
        self.agent = agent
        # Frames for the phone are queued so a slow phone never blocks the
        # daemon's agent socket, which every stream and request shares.
        self.outbox: asyncio.Queue = asyncio.Queue()
        self.last_activity = time.monotonic()
        self.bytes_up = 0
        self.bytes_down = 0
        self.ended: asyncio.Future = asyncio.get_running_loop().create_future()

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def end(self, code: int, reason: str, *, notify_agent: bool, phone_gone: bool = False) -> None:
        """Record why the stream ends. The first caller wins."""
        if not self.ended.done():
            self.ended.set_result((code, reason, notify_agent, phone_gone))


hub = RelayHub()
router = APIRouter()


class RelayRequest(BaseModel):
    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class RelayResponse(BaseModel):
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


def _token_ok(authorization: str | None, expected: str) -> bool:
    import hmac

    if not authorization:
        return False
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return hmac.compare_digest(parts[1].strip(), expected)


@router.websocket("/v1/relay/agent")
async def relay_agent(ws: WebSocket) -> None:
    """The daemon's outbound tunnel. Authenticated by the shared Courier token
    (only real daemons hold it) AND by proving key-id ownership at register."""
    import os

    expected = os.environ.get("COURIER_API_TOKEN", "").strip()
    if not expected or not _token_ok(ws.headers.get("authorization"), expected):
        await ws.close(code=4401)  # unauthorized
        return
    await ws.accept()

    try:
        register_frame = await ws.receive_json()
    except Exception:  # noqa: BLE001
        await ws.close(code=4400)
        return
    key_id = verify_register(register_frame)
    if key_id is None:
        await ws.close(code=4401)
        return

    displaced = hub.register(key_id, ws)
    if displaced is not None:
        hub.end_streams_for(displaced, 1001, "daemon reconnected")
        try:
            await displaced.close(code=4409)  # replaced by a newer tunnel
        except Exception:  # noqa: BLE001
            pass
    await ws.send_json({"type": "registered"})
    logger.info("relay_agent_registered", extra={"key_id": key_id[:8], "agents": hub.agent_count()})

    try:
        while True:
            msg = await ws.receive_json()
            mtype = msg.get("type") if isinstance(msg, dict) else None
            if mtype == "response" and isinstance(msg.get("id"), str):
                hub.resolve(msg["id"], msg)
            elif mtype == "stream.data" and isinstance(msg.get("sid"), str) and isinstance(msg.get("data"), str):
                hub.stream_data_from_agent(ws, msg["sid"], msg["data"])
            elif mtype == "stream.close" and isinstance(msg.get("sid"), str):
                hub.stream_close_from_agent(ws, msg["sid"], msg.get("code"), msg.get("reason"))
            elif mtype == "ping":
                await ws.send_json({"type": "pong"})
            # ignore anything else
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("relay_agent_error", extra={"key_id": key_id[:8]})
    finally:
        hub.unregister(key_id, ws)
        hub.end_streams_for(ws, 4404, "daemon disconnected")
        logger.info("relay_agent_disconnected", extra={"key_id": key_id[:8], "agents": hub.agent_count()})


@router.post("/v1/relay/{key_id}/req", response_model=RelayResponse)
async def relay_forward(key_id: str, req: RelayRequest) -> RelayResponse:
    """The app's off-LAN request path. Courier forwards opaque signed bytes to
    the daemon addressed by key id and returns its signed reply."""
    if not any(req.path == p or req.path.startswith(p) for p in ALLOWED_PREFIXES):
        raise HTTPException(status_code=403, detail="path not allowed over the relay")
    frame = await hub.forward(
        key_id,
        {"method": req.method, "path": req.path, "headers": req.headers, "body": req.body},
    )
    return RelayResponse(
        status=int(frame.get("status", 502)),
        headers={str(k): str(v) for k, v in (frame.get("headers") or {}).items()},
        body=frame.get("body"),
    )


async def _pump_phone_to_agent(stream: _Stream) -> None:
    while True:
        message = await stream.phone.receive()
        if message["type"] == "websocket.disconnect":
            stream.end(message.get("code") or 1005, message.get("reason") or "", notify_agent=True, phone_gone=True)
            return
        text = message.get("text")
        if text is None:
            stream.end(1003, "binary frames are not supported", notify_agent=True)
            return
        size = len(text.encode("utf-8"))
        if size > STREAM_MAX_FRAME_BYTES:
            stream.end(1009, "frame too large", notify_agent=True)
            return
        stream.touch()
        stream.bytes_up += size
        try:
            await stream.agent.send_json({"type": "stream.data", "sid": stream.sid, "data": text})
        except Exception:  # noqa: BLE001 - a failed write means the daemon socket is gone
            stream.end(4404, "daemon not connected", notify_agent=False)
            return


async def _pump_agent_to_phone(stream: _Stream) -> None:
    while True:
        kind, payload = await stream.outbox.get()
        if kind == "close":
            code, reason = payload
            stream.end(code, reason, notify_agent=False)
            return
        await stream.phone.send_text(payload)
        stream.bytes_down += len(payload.encode("utf-8"))


async def _guarded(pump, stream: _Stream) -> None:
    """Run a pump so that an unexpected error ends the stream instead of
    leaving it open until the idle timeout."""
    try:
        await pump(stream)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("relay_stream_error", extra=log_fields(sid=stream.sid, key_id=stream.key_id[:8], error=type(exc).__name__))
        stream.end(1011, "relay error", notify_agent=True)


@router.websocket("/v1/relay/{key_id}/stream")
async def relay_stream(ws: WebSocket, key_id: str) -> None:
    """A phone's live stream to its daemon. Courier only routes opaque text
    frames; the end-to-end handshake and encryption happen phone <-> daemon."""
    await ws.accept()
    opened = hub.open_stream(key_id, ws)
    if isinstance(opened, int):
        logger.info("relay_stream_rejected", extra=log_fields(key_id=key_id[:8], code=opened))
        await ws.close(code=opened)
        return
    stream = opened
    try:
        await stream.agent.send_json({"type": "stream.open", "sid": stream.sid})
    except Exception:  # noqa: BLE001 - a failed write means the daemon socket is gone
        hub.remove_stream(stream)
        logger.info("relay_stream_rejected", extra=log_fields(key_id=key_id[:8], code=4404))
        await ws.close(code=4404)
        return
    logger.info("relay_stream_opened", extra=log_fields(sid=stream.sid, key_id=key_id[:8]))
    pumps = [
        asyncio.create_task(_guarded(_pump_phone_to_agent, stream)),
        asyncio.create_task(_guarded(_pump_agent_to_phone, stream)),
    ]
    try:
        while not stream.ended.done():
            remaining = stream.last_activity + STREAM_IDLE_S - time.monotonic()
            if remaining <= 0:
                stream.end(4408, "idle timeout", notify_agent=True)
                break
            await asyncio.wait([stream.ended], timeout=remaining)
    finally:
        for pump in pumps:
            pump.cancel()
        hub.remove_stream(stream)
    await _finish_stream(stream)


async def _finish_stream(stream: _Stream) -> None:
    code, reason, notify_agent, phone_gone = stream.ended.result()
    if notify_agent:
        try:
            await stream.agent.send_json({"type": "stream.close", "sid": stream.sid, "code": code, "reason": reason})
        except Exception:  # noqa: BLE001 - the daemon socket may already be gone
            pass
    if not phone_gone:
        try:
            await stream.phone.close(code=code, reason=reason)
        except Exception:  # noqa: BLE001 - the phone may already be gone
            pass
    logger.info(
        "relay_stream_closed",
        extra=log_fields(
            sid=stream.sid,
            key_id=stream.key_id[:8],
            code=code,
            bytes_up=stream.bytes_up,
            bytes_down=stream.bytes_down,
        ),
    )


@router.get("/v1/relay/{key_id}/status")
async def relay_status(key_id: str) -> dict[str, Any]:
    """Cheap reachability probe the app can use before falling back to the relay."""
    return {"online": hub.is_online(key_id)}
