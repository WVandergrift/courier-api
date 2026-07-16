from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def _configure(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("COURIER_API_TOKEN", "admin-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")
    import app.oelo_diagnostics as diagnostics

    with diagnostics._lock:
        diagnostics._sessions.clear()


def _create(client: TestClient, hardware_id: str = "AABBCCDDEEFF", ttl: int = 600) -> dict:
    response = client.post(
        "/v1/diagnostics/oelo/sessions",
        headers={"Authorization": "Bearer admin-token"},
        json={"hardwareId": hardware_id, "ttlSeconds": ttl},
    )
    assert response.status_code == 200
    return response.json()


def test_session_creation_requires_admin_auth(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/v1/diagnostics/oelo/sessions",
            json={"hardwareId": "AABBCCDDEEFF"},
        )

    assert response.status_code == 401


def test_ingest_token_is_bound_to_session_and_tail_requires_admin(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    with TestClient(app) as client:
        session = _create(client, hardware_id="aabbccddeeff")
        wrong = client.post(
            session["ingestPath"],
            headers={"Authorization": "Bearer wrong-token", "Content-Type": "text/plain"},
            content="wrong\n",
        )
        accepted = client.post(
            session["ingestPath"],
            headers={"Authorization": f"Bearer {session['ingestToken']}", "Content-Type": "text/plain"},
            content="booting\nconnected\n",
        )
        unauthorized_tail = client.get(session["tailPath"])
        tail = client.get(
            session["tailPath"],
            headers={"Authorization": "Bearer admin-token"},
        )

    assert session["hardwareId"] == "AABBCCDDEEFF"
    assert accepted.headers["cache-control"] == "no-store"
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json() == {"accepted": 2, "nextCursor": 2}
    assert unauthorized_tail.status_code == 401
    assert tail.status_code == 200
    assert tail.headers["cache-control"] == "no-store"
    assert [line["text"] for line in tail.json()["lines"]] == ["booting", "connected"]


def test_tail_cursor_and_session_delete(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    with TestClient(app) as client:
        session = _create(client)
        ingest_headers = {
            "Authorization": f"Bearer {session['ingestToken']}",
            "Content-Type": "text/plain",
        }
        client.post(session["ingestPath"], headers=ingest_headers, content="one\ntwo\nthree\n")
        tail = client.get(
            f"{session['tailPath']}?after=1&limit=1",
            headers={"Authorization": "Bearer admin-token"},
        )
        deleted = client.delete(
            f"/v1/diagnostics/oelo/sessions/{session['sessionId']}",
            headers={"Authorization": "Bearer admin-token"},
        )
        missing = client.get(
            session["tailPath"],
            headers={"Authorization": "Bearer admin-token"},
        )

    assert tail.json()["nextCursor"] == 2
    assert [line["text"] for line in tail.json()["lines"]] == ["two"]
    assert deleted.status_code == 204
    assert missing.status_code == 404


def test_sessions_expire_without_persisting_logs(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    import app.oelo_diagnostics as diagnostics

    now = 1_700_000_000.0
    monkeypatch.setattr(diagnostics, "_clock", lambda: now)
    with TestClient(app) as client:
        session = _create(client, ttl=30)
        now += 31
        expired = client.post(
            session["ingestPath"],
            headers={"Authorization": f"Bearer {session['ingestToken']}"},
            content="late\n",
        )

    assert expired.status_code == 404


def test_ingest_rejects_oversized_batches(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    with TestClient(app) as client:
        session = _create(client)
        response = client.post(
            session["ingestPath"],
            headers={"Authorization": f"Bearer {session['ingestToken']}"},
            content=b"x" * (16 * 1024 + 1),
        )

    assert response.status_code == 413
