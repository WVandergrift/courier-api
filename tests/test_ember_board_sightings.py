from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from app.apns import ApnsResult
from app.ember_board_sightings import board_sighting_message
from app.ember_identity import enrollment_message, key_thumbprint
from app.ember_push import (
    EMBER_APNS_TOPIC,
    configure_ember_push,
    member_push_token_message,
)
from app.main import app


CONTROLLER_ID = "AABBCCDDEEFF"
TAG_ID = "tag_01J2NFCEMBERCORE"
BOARD_NAME = "Ember Core 64EC"
BOARD_SUFFIX = "A78D12"
DEVICE_TOKEN = "ab" * 32
PUSH_TOKEN_KEY = base64.urlsafe_b64encode(b"k" * 32).decode("ascii")


class FakeApnsClient:
    def __init__(self, result: ApnsResult | None = None) -> None:
        self.requests = []
        self.result = result or ApnsResult(
            success=True, status_code=200, apns_id="ember-board-apns-1"
        )

    async def send(self, request):
        self.requests.append(request)
        return self.result


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _public_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    return _b64u(
        private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def _sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")
    monkeypatch.setenv("EMBER_PUSH_TOKEN_KEY", PUSH_TOKEN_KEY)
    return TestClient(app)


def _create_home(
    client: TestClient,
    controller_key: ec.EllipticCurvePrivateKey,
    client_key: ec.EllipticCurvePrivateKey,
) -> dict:
    bootstrap = client.post(
        "/v1/ember/controller-bootstraps",
        headers={"Authorization": "Bearer test-token"},
        json={
            "controllerId": CONTROLLER_ID,
            "tagId": TAG_ID,
            "publicKey": _public_key(controller_key),
            "hardwareModel": "oelo_esp32",
            "attestation": "retrofit",
        },
    )
    assert bootstrap.status_code == 200
    challenge_response = client.post(
        "/v1/ember/enrollment-challenges",
        json={
            "controllerId": CONTROLLER_ID,
            "tagId": TAG_ID,
            "proofMethod": "home_key_ble",
            "clientPublicKey": _public_key(client_key),
        },
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.json()
    signature = _sign(
        controller_key,
        enrollment_message(
            challenge["proofMethod"],
            challenge["challengeId"],
            CONTROLLER_ID,
            TAG_ID,
            key_thumbprint(_public_key(client_key)),
            challenge["serverNonce"],
        ),
    )
    completed = client.post(
        f"/v1/ember/enrollment-challenges/{challenge['challengeId']}/complete",
        json={"controllerSignature": signature, "clientName": "Will's iPhone"},
    )
    assert completed.status_code == 200
    return completed.json()


def _register_push_token(
    client: TestClient,
    home: dict,
    client_key: ec.EllipticCurvePrivateKey,
) -> None:
    requested_at = _iso(datetime.now(UTC))
    message = member_push_token_message(
        "register",
        home["installationId"],
        home["memberId"],
        "ios",
        "sandbox",
        EMBER_APNS_TOPIC,
        DEVICE_TOKEN,
        requested_at,
    )
    response = client.post(
        "/v1/ember/member-push-tokens",
        json={
            "installationId": home["installationId"],
            "memberId": home["memberId"],
            "platform": "ios",
            "environment": "sandbox",
            "appTopic": EMBER_APNS_TOPIC,
            "deviceToken": DEVICE_TOKEN,
            "requestedAt": requested_at,
            "clientSignature": _sign(client_key, message),
        },
    )
    assert response.status_code == 200


def _sighting_payload(
    controller_key: ec.EllipticCurvePrivateKey,
    installation_id: str,
    observed_at: str,
    *,
    signature_key: ec.EllipticCurvePrivateKey | None = None,
) -> dict:
    median_rssi = "-56"
    message = board_sighting_message(
        CONTROLLER_ID,
        installation_id,
        BOARD_NAME,
        BOARD_SUFFIX,
        observed_at,
        median_rssi,
    )
    return {
        "controllerId": CONTROLLER_ID,
        "installationId": installation_id,
        "boardName": BOARD_NAME,
        "boardSuffix": BOARD_SUFFIX,
        "observedAt": observed_at,
        "medianRssi": median_rssi,
        "controllerSignature": _sign(signature_key or controller_key, message),
    }


def test_signed_sighting_pushes_active_home_member(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    fake_apns = FakeApnsClient()
    with _client(monkeypatch, tmp_path) as client:
        configure_ember_push(fake_apns)
        home = _create_home(client, controller_key, client_key)
        _register_push_token(client, home, client_key)
        response = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key, home["installationId"], _iso(datetime.now(UTC))
            ),
        )

    assert response.status_code == 200
    assert response.json()["protocol"] == "ember-board-sighting-v1"
    assert response.json()["accepted"] is True
    assert response.json()["notificationQueued"] is True
    assert len(fake_apns.requests) == 1
    push = fake_apns.requests[0]
    assert push.device_token == DEVICE_TOKEN
    assert push.topic == EMBER_APNS_TOPIC
    assert push.environment == "sandbox"
    assert push.collapse_id == f"board-{BOARD_SUFFIX}"
    assert push.payload == {
        "aps": {
            "alert": {
                "title": "New Ember Core found near your home",
                "body": "Open Ember to set it up.",
            },
            "sound": "default",
            "thread-id": "ember-new-board",
        },
        "kind": "ember-board-sighting",
        "boardName": BOARD_NAME,
        "boardSuffix": BOARD_SUFFIX,
    }
    with sqlite3.connect(tmp_path / "courier.db") as conn:
        sighting = conn.execute(
            """SELECT controller_id, installation_id, board_suffix,
                      median_rssi, notification_queued
               FROM ember_board_sightings"""
        ).fetchone()
        event = conn.execute(
            "SELECT status, payload_json, device_token_hash FROM push_events"
        ).fetchone()
    assert sighting == (
        CONTROLLER_ID,
        home["installationId"],
        BOARD_SUFFIX,
        -56,
        1,
    )
    assert event[0] == "sent"
    assert json.loads(event[1])["kind"] == "ember-board-sighting"
    assert event[2] == hashlib.sha256(DEVICE_TOKEN.encode("ascii")).hexdigest()


def test_replay_is_rejected_but_fresh_duplicate_is_accepted_without_push(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    fake_apns = FakeApnsClient()
    observed_at = datetime.now(UTC)
    with _client(monkeypatch, tmp_path) as client:
        configure_ember_push(fake_apns)
        home = _create_home(client, controller_key, client_key)
        _register_push_token(client, home, client_key)
        first_payload = _sighting_payload(
            controller_key, home["installationId"], _iso(observed_at)
        )
        first = client.post("/v1/ember/board-sightings", json=first_payload)
        replay = client.post("/v1/ember/board-sightings", json=first_payload)
        duplicate = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key,
                home["installationId"],
                _iso(observed_at + timedelta(seconds=1)),
            ),
        )
        with sqlite3.connect(tmp_path / "courier.db") as conn:
            conn.execute(
                "UPDATE ember_board_notification_windows SET last_queued_at = ?",
                (_iso(observed_at - timedelta(hours=25)),),
            )
            conn.commit()
        after_window = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key,
                home["installationId"],
                _iso(observed_at + timedelta(seconds=2)),
            ),
        )

    assert first.status_code == 200
    assert replay.status_code == 409
    assert duplicate.status_code == 200
    assert duplicate.json()["notificationQueued"] is False
    assert after_window.status_code == 200
    assert after_window.json()["notificationQueued"] is True
    assert len(fake_apns.requests) == 2
    with sqlite3.connect(tmp_path / "courier.db") as conn:
        rows = conn.execute(
            "SELECT notification_queued FROM ember_board_sightings ORDER BY received_at"
        ).fetchall()
    assert rows == [(1,), (0,), (1,)]


def test_sighting_rejects_wrong_identity_signature_and_stale_time(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        home = _create_home(client, controller_key, client_key)
        now = datetime.now(UTC)
        wrong_installation = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(controller_key, "another-installation", _iso(now)),
        )
        bad_signature = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key,
                home["installationId"],
                _iso(now + timedelta(seconds=1)),
                signature_key=other_key,
            ),
        )
        stale = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key,
                home["installationId"],
                _iso(now - timedelta(minutes=11)),
            ),
        )

    assert wrong_installation.status_code == 403
    assert bad_signature.status_code == 403
    assert stale.status_code == 422


def test_sighting_without_registered_members_does_not_consume_push_window(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    fake_apns = FakeApnsClient()
    with _client(monkeypatch, tmp_path) as client:
        configure_ember_push(fake_apns)
        home = _create_home(client, controller_key, client_key)
        response = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key, home["installationId"], _iso(datetime.now(UTC))
            ),
        )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["notificationQueued"] is False
    assert fake_apns.requests == []
    with sqlite3.connect(tmp_path / "courier.db") as conn:
        windows = conn.execute(
            "SELECT COUNT(*) FROM ember_board_notification_windows"
        ).fetchone()[0]
    assert windows == 0


def test_invalid_board_sighting_push_token_is_revoked(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    fake_apns = FakeApnsClient(
        ApnsResult(
            success=False,
            status_code=410,
            invalid_token=True,
            error_code="Unregistered",
            error_message="Unregistered",
        )
    )
    with _client(monkeypatch, tmp_path) as client:
        configure_ember_push(fake_apns)
        home = _create_home(client, controller_key, client_key)
        _register_push_token(client, home, client_key)
        response = client.post(
            "/v1/ember/board-sightings",
            json=_sighting_payload(
                controller_key, home["installationId"], _iso(datetime.now(UTC))
            ),
        )

    assert response.status_code == 200
    with sqlite3.connect(tmp_path / "courier.db") as conn:
        token = conn.execute(
            "SELECT revoked_at FROM ember_member_push_tokens"
        ).fetchone()
        event = conn.execute(
            "SELECT status, invalid_token FROM push_events"
        ).fetchone()
    assert token[0] is not None
    assert event == ("failed", 1)
