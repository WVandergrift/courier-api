from __future__ import annotations

import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient

from app.apns import ApnsClient, ApnsResult
from app.main import app


class FakeApnsClient:
    def __init__(self) -> None:
        self.requests = []

    async def send(self, request):
        self.requests.append(request)
        return ApnsResult(success=True, status_code=200, apns_id="apns-1")

    async def close(self):
        return None


def test_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")

    with TestClient(app) as client:
        response = client.post("/v1/push/ios", json={})

    assert response.status_code == 401


def test_ember_home_key_association_files_and_landing_page(tmp_path, monkeypatch):
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")
    monkeypatch.setenv(
        "EMBER_ANDROID_CERT_SHA256",
        "AA:BB:CC",
    )
    with TestClient(app) as client:
        home = client.get("/")
        apple = client.get("/.well-known/apple-app-site-association")
        android = client.get("/.well-known/assetlinks.json")
        landing = client.get("/ember/t/tag_01J2NFCEMBERCORE")
        invalid = client.get("/ember/t/short")

    assert home.status_code == 200
    assert "Light belongs at home." in home.text
    assert "Set up and control compatible architectural lighting" in home.text
    assert "Set up, control, and recover" not in home.text
    assert "Simple for consumers. Open for developers." in home.text
    assert "house-lights" not in home.text
    assert 'class="strip ' not in home.text
    assert "roof-chase" not in home.text
    assert "Recover gracefully. Fail softly." not in home.text
    assert "https://flash.emberhome.lighting" in home.text
    assert apple.status_code == 200
    assert apple.headers["content-type"].startswith("application/json")
    assert apple.json()["applinks"]["details"][0] == {
        "appID": "3YWE9TBUAM.app.embercore",
        "paths": ["/ember/t/*"],
    }
    assert apple.json()["applinks"]["details"][1:] == [{
        "appID": "3YWE9TBUAM.com.apa.pulse-meta-sample",
        "paths": ["/pulse-meta"],
    }]
    target = android.json()[0]["target"]
    assert target["package_name"] == "app.embercore"
    assert "AA:BB:CC" in target["sha256_cert_fingerprints"]
    assert landing.status_code == 200
    assert landing.headers["referrer-policy"] == "no-referrer"
    assert landing.text.startswith("<!doctype html>")
    assert "<body><h1>Ember Home Key</h1>" in landing.text
    assert "tag_01J2NFCEMBERCORE" not in landing.text
    assert invalid.status_code == 404


def test_sends_push_and_records_event(tmp_path, monkeypatch):
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")

    fake = FakeApnsClient()
    import app.main as main

    with TestClient(app) as client:
        main.apns_client = fake
        response = client.post(
            "/v1/push/ios",
            headers={"Authorization": "Bearer test-token"},
            json={
                "deviceToken": "abcdef1234567890abcdef1234567890",
                "apnsTopic": "systems.courier.demo",
                "environment": "sandbox",
                "title": "Hello",
                "body": "World",
                "data": {"kind": "test"},
            },
        )

    assert response.status_code == 200
    assert response.json()["apnsId"] == "apns-1"
    assert fake.requests[0].topic == "systems.courier.demo"
    assert fake.requests[0].payload["aps"]["alert"]["title"] == "Hello"
    # Custom data is nested under top-level "body" — expo-notifications reads
    # remote content.data ONLY from userInfo["body"], never top-level keys.
    assert fake.requests[0].payload["body"] == {"kind": "test"}
    assert "kind" not in fake.requests[0].payload


@pytest.mark.parametrize(
    "options, expected_aps, expected_push_type, expected_priority",
    [
        ({}, {"sound": "default"}, "alert", "10"),
        ({"contentAvailable": False}, {"sound": "default"}, "alert", "10"),
        ({"contentAvailable": True, "sound": None}, {"content-available": 1}, "alert", "10"),
        ({"pushType": "background"}, {"content-available": 1}, "background", "5"),
        ({"pushType": "background", "contentAvailable": False}, {"content-available": 1}, "background", "5"),
    ],
    ids=["default-alert", "explicit-false", "silent-alert-background-delivery", "background", "background-explicit-false"],
)
def test_push_content_available_preserves_payload_and_apns_headers(
    tmp_path, monkeypatch, options, expected_aps, expected_push_type, expected_priority
):
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    requests = []

    def receive_apns(request):
        requests.append(request)
        return httpx.Response(200, headers={"apns-id": "apns-content-available"})

    apns = ApnsClient(
        team_id="TEAM",
        key_id="KEY",
        private_key="PRIVATE",
        client=httpx.AsyncClient(transport=httpx.MockTransport(receive_apns)),
    )
    monkeypatch.setattr(ApnsClient, "from_env", classmethod(lambda cls: apns))
    monkeypatch.setattr(apns, "_authorization_token", lambda: "test-provider-token")
    payload = {
        "deviceToken": "abcdef1234567890abcdef1234567890",
        "apnsTopic": "com.apa.pulse-meta-sample",
        "data": {"kind": "glasses.card", "title": "Build complete"},
        **options,
    }
    if expected_push_type == "alert":
        payload.update(title="Pulse", body="Build complete")
        expected_aps = {**expected_aps, "alert": {"title": "Pulse", "body": "Build complete"}}

    with TestClient(app) as client:
        response = client.post(
            "/v1/push/ios", headers={"Authorization": "Bearer test-token"}, json=payload
        )

    assert response.status_code == 200
    assert len(requests) == 1
    outbound = requests[0]
    assert json.loads(outbound.content) == {"aps": expected_aps, "body": payload["data"]}
    assert outbound.headers["apns-push-type"] == expected_push_type
    assert outbound.headers["apns-priority"] == expected_priority
    assert outbound.headers["apns-topic"] == "com.apa.pulse-meta-sample"


def test_category_and_thread_id_land_in_aps(tmp_path, monkeypatch):
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")

    fake = FakeApnsClient()
    import app.main as main

    with TestClient(app) as client:
        main.apns_client = fake
        response = client.post(
            "/v1/push/ios",
            headers={"Authorization": "Bearer test-token"},
            json={
                "deviceToken": "abcdef1234567890abcdef1234567890",
                "apnsTopic": "systems.courier.demo",
                "title": "RAC-1633 needs input",
                "body": "Proceed anyway?",
                "category": "PULSE_QUESTION",
                "threadId": "rac-1633",
                "data": {"questionId": "q-1", "options": ["Proceed anyway", "Wait for approval"]},
            },
        )

    assert response.status_code == 200
    aps = fake.requests[0].payload["aps"]
    # The category is what makes iOS render the registered interactive actions.
    assert aps["category"] == "PULSE_QUESTION"
    # thread-id groups a ticket's pushes into one notification thread.
    assert aps["thread-id"] == "rac-1633"
    # Custom keys ride under "body" so expo-notifications surfaces them in
    # content.data (it reads remote data from userInfo["body"] only).
    body = fake.requests[0].payload["body"]
    assert body["questionId"] == "q-1"
    assert body["options"] == ["Proceed anyway", "Wait for approval"]


def test_basic_auth_uses_password(tmp_path, monkeypatch):
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")

    import app.main as main

    with TestClient(app) as client:
        main.apns_client = FakeApnsClient()
        response = client.post(
            "/v1/push/ios",
            auth=("courier", "test-token"),
            json={
                "deviceToken": "abcdef1234567890abcdef1234567890",
                "apnsTopic": "systems.courier.demo",
                "title": "Hello",
            },
        )

    assert response.status_code == 200
