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

logger = logging.getLogger("courier.relay")

REGISTER_SKEW_MS = 5 * 60 * 1000
FORWARD_TIMEOUT_S = 20.0
# Only these path prefixes may be relayed to a daemon — the companion API and
# the unpair route. Keeps the tunnel from being used to probe other surfaces.
ALLOWED_PREFIXES = ("/v1/companion/", "/client")


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
            elif mtype == "ping":
                await ws.send_json({"type": "pong"})
            # ignore anything else
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("relay_agent_error", extra={"key_id": key_id[:8]})
    finally:
        hub.unregister(key_id, ws)
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


@router.get("/v1/relay/{key_id}/status")
async def relay_status(key_id: str) -> dict[str, Any]:
    """Cheap reachability probe the app can use before falling back to the relay."""
    return {"online": hub.is_online(key_id)}
