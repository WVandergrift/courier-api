from __future__ import annotations

import asyncio
import contextlib
import json
import base64
import time

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.relay as relay
from app.main import app
from app.relay import RelayHub, hub, verify_register


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_agent():
    """A device/daemon-style Ed25519 identity and a signed register frame."""
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    key_id = _b64u(pub_raw)

    def register_frame(ts: int | None = None) -> dict:
        ts = ts if ts is not None else int(time.time() * 1000)
        msg = f"pulse-relay-register/v1\n{key_id}\n{ts}".encode()
        sig = priv.sign(msg)
        return {"type": "register", "keyId": key_id, "ts": ts, "sig": _b64u(sig)}

    return key_id, register_frame


# --- verify_register -------------------------------------------------------


def test_verify_register_accepts_a_valid_frame():
    key_id, register_frame = make_agent()
    assert verify_register(register_frame()) == key_id


def test_verify_register_rejects_a_tampered_or_expired_frame():
    key_id, register_frame = make_agent()
    frame = register_frame()

    tampered = {**frame, "keyId": key_id[:-1] + ("A" if key_id[-1] != "A" else "B")}
    assert verify_register(tampered) is None

    bad_sig = {**frame, "sig": _b64u(b"\x00" * 64)}
    assert verify_register(bad_sig) is None

    expired = register_frame(ts=int(time.time() * 1000) - 10 * 60 * 1000)
    assert verify_register(expired) is None

    assert verify_register({"type": "nope"}) is None
    assert verify_register("not a dict") is None


# --- RelayHub --------------------------------------------------------------


class FakeAgent:
    """Stands in for a connected daemon socket. Its send_json optionally
    resolves the forward future immediately (an instant daemon)."""

    def __init__(self, hub_ref: RelayHub, responder=None):
        self.hub = hub_ref
        self.responder = responder
        self.sent: list[dict] = []
        self.closed_with: int | None = None

    async def send_json(self, frame: dict):
        self.sent.append(frame)
        if self.responder and frame.get("type") == "request":
            self.hub.resolve(frame["id"], self.responder(frame))

    async def close(self, code: int = 1000):
        self.closed_with = code


def test_register_replaces_and_reports_online():
    h = RelayHub()
    a, b = FakeAgent(h), FakeAgent(h)
    assert h.register("k", a) is None
    assert h.is_online("k") is True
    # a newer socket displaces the old one (returned so the caller can close it)
    assert h.register("k", b) is a
    h.unregister("k", a)  # stale socket disconnecting must NOT drop the new one
    assert h.is_online("k") is True
    h.unregister("k", b)
    assert h.is_online("k") is False


def test_forward_round_trips_a_response():
    async def go():
        h = RelayHub()
        h.register("k", FakeAgent(h, lambda f: {"type": "response", "id": f["id"], "status": 200, "headers": {"x-pulse-sig": "s"}, "body": "sealed"}))
        return await h.forward("k", {"method": "GET", "path": "/v1/companion/envs", "headers": {}, "body": None})

    frame = asyncio.run(go())
    assert frame["status"] == 200
    assert frame["headers"]["x-pulse-sig"] == "s"
    assert frame["body"] == "sealed"


def test_forward_502_when_daemon_offline():
    async def go():
        await RelayHub().forward("nobody", {"method": "GET", "path": "/x", "headers": {}, "body": None})

    with pytest.raises(HTTPException) as ei:
        asyncio.run(go())
    assert ei.value.status_code == 502


def test_forward_504_on_timeout(monkeypatch):
    monkeypatch.setattr(relay, "FORWARD_TIMEOUT_S", 0.05)

    async def go():
        h = RelayHub()
        h.register("k", FakeAgent(h, responder=None))  # never resolves
        await h.forward("k", {"method": "GET", "path": "/v1/companion/envs", "headers": {}, "body": None})

    with pytest.raises(HTTPException) as ei:
        asyncio.run(go())
    assert ei.value.status_code == 504


# --- HTTP forward endpoint (through the app) -------------------------------


def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")
    return TestClient(app)


def test_relay_forward_endpoint_returns_daemon_reply(monkeypatch, tmp_path):
    agent = FakeAgent(hub, lambda f: {"type": "response", "id": f["id"], "status": 200, "headers": {"x-pulse-sig": "sig"}, "body": "sealed-envelope"})
    hub.register("KID", agent)
    try:
        with _client(monkeypatch, tmp_path) as client:
            r = client.post("/v1/relay/KID/req", json={"method": "GET", "path": "/v1/companion/envs", "headers": {"x-pulse-client": "c"}, "body": None})
        assert r.status_code == 200
        assert r.json() == {"status": 200, "headers": {"x-pulse-sig": "sig"}, "body": "sealed-envelope"}
        # the forwarded frame carried the app's signed headers verbatim
        fwd = agent.sent[0]
        assert fwd["method"] == "GET" and fwd["path"] == "/v1/companion/envs"
        assert fwd["headers"]["x-pulse-client"] == "c"
    finally:
        hub.unregister("KID", agent)


def test_relay_forward_rejects_disallowed_paths(monkeypatch, tmp_path):
    agent = FakeAgent(hub, lambda f: {"type": "response", "id": f["id"], "status": 200, "headers": {}, "body": None})
    hub.register("KID", agent)
    try:
        with _client(monkeypatch, tmp_path) as client:
            r = client.post("/v1/relay/KID/req", json={"method": "GET", "path": "/internal/config", "headers": {}, "body": None})
        assert r.status_code == 403
    finally:
        hub.unregister("KID", agent)


def test_relay_forward_502_when_offline(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        r = client.post("/v1/relay/ghost/req", json={"method": "GET", "path": "/v1/companion/envs", "headers": {}, "body": None})
    assert r.status_code == 502


def test_relay_status_reports_presence(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        assert client.get("/v1/relay/ghost/status").json() == {"online": False}


# --- WS agent handshake ----------------------------------------------------


def test_ws_agent_rejects_without_token(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        with pytest.raises(Exception):
            with client.websocket_connect("/v1/relay/agent") as ws:
                ws.receive_json()


def test_ws_agent_registers_and_pongs(monkeypatch, tmp_path):
    key_id, register_frame = make_agent()
    with _client(monkeypatch, tmp_path) as client:
        with client.websocket_connect("/v1/relay/agent", headers={"authorization": "Bearer test-token"}) as ws:
            ws.send_json(register_frame())
            assert ws.receive_json() == {"type": "registered"}
            assert hub.is_online(key_id) is True
            ws.send_json({"type": "ping"})
            assert ws.receive_json() == {"type": "pong"}
    # socket closed → deregistered
    assert hub.is_online(key_id) is False


# --- WS phone stream -------------------------------------------------------

AGENT_AUTH = {"authorization": "Bearer test-token"}


def recv(ws, timeout: float = 2.0) -> dict:
    """Receive the next ASGI message the app sent on a TestClient socket, failing
    instead of hanging when nothing arrives. Reads the session's private queue
    because TestClient's public receive() has no timeout."""

    async def _receive():
        with anyio.fail_after(timeout):
            return await ws._send_rx.receive()

    return ws.portal.call(_receive)


def recv_json(ws, timeout: float = 2.0):
    message = recv(ws, timeout)
    assert message["type"] == "websocket.send", message
    return json.loads(message["text"])


def test_stream_closes_4404_when_no_daemon_is_registered(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        with client.websocket_connect("/v1/relay/ghost/stream") as phone:
            message = recv(phone)
    assert message["type"] == "websocket.close"
    assert message["code"] == 4404


@contextlib.contextmanager
def registered_agent(client):
    """A real daemon agent socket, registered and ready. Yields (ws, key_id)."""
    key_id, register_frame = make_agent()
    with client.websocket_connect("/v1/relay/agent", headers=AGENT_AUTH) as ws:
        ws.send_json(register_frame())
        assert recv_json(ws) == {"type": "registered"}
        yield ws, key_id


def open_stream(client, agent, key_id, stack):
    """Open a phone stream and return (phone_ws, sid) from the daemon's stream.open."""
    phone = stack.enter_context(client.websocket_connect(f"/v1/relay/{key_id}/stream"))
    opened = recv_json(agent)
    assert opened["type"] == "stream.open"
    return phone, opened["sid"]


def test_stream_announces_open_and_forwards_phone_text_to_the_daemon(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client, registered_agent(client) as (agent, key_id), contextlib.ExitStack() as stack:
        phone, sid = open_stream(client, agent, key_id, stack)
        assert isinstance(sid, str) and sid

        phone.send_text('{"t":"hello","v":1}')
        assert recv_json(agent) == {"type": "stream.data", "sid": sid, "data": '{"t":"hello","v":1}'}


def test_stream_delivers_daemon_data_to_the_phone_as_text(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client, registered_agent(client) as (agent, key_id), contextlib.ExitStack() as stack:
        phone, sid = open_stream(client, agent, key_id, stack)

        agent.send_json({"type": "stream.data", "sid": sid, "data": '{"t":"welcome","v":1}'})
        assert recv(phone) == {"type": "websocket.send", "text": '{"t":"welcome","v":1}'}


def test_daemon_stream_close_closes_the_phone_with_its_code_after_queued_data(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client, registered_agent(client) as (agent, key_id), contextlib.ExitStack() as stack:
        phone, sid = open_stream(client, agent, key_id, stack)

        agent.send_json({"type": "stream.data", "sid": sid, "data": "last"})
        agent.send_json({"type": "stream.close", "sid": sid, "code": 4401, "reason": "handshake rejected"})
        assert recv(phone) == {"type": "websocket.send", "text": "last"}
        closed = recv(phone)
        assert closed["type"] == "websocket.close"
        assert (closed["code"], closed["reason"]) == (4401, "handshake rejected")


def test_phone_disconnect_sends_stream_close_to_the_daemon(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client, registered_agent(client) as (agent, key_id), contextlib.ExitStack() as stack:
        phone, sid = open_stream(client, agent, key_id, stack)

        phone.close(code=4400, reason="bad tag")
        assert recv_json(agent) == {"type": "stream.close", "sid": sid, "code": 4400, "reason": "bad tag"}
        agent.send_json({"type": "ping"})
        assert recv_json(agent) == {"type": "pong"}
