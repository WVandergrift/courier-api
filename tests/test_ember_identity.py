from __future__ import annotations

import base64
import sqlite3
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from app.db import connect, init_db
from app.ember_identity import enrollment_message, key_thumbprint
from app.main import app


CONTROLLER_ID = "AABBCCDDEEFF"
TAG_ID = "tag_01J2NFCEMBERCORE"


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


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("COURIER_API_TOKEN", "test-token")
    monkeypatch.setenv("COURIER_DB_PATH", str(tmp_path / "courier.db"))
    monkeypatch.setenv("APNS_TEAM_ID", "TEAM")
    monkeypatch.setenv("APNS_KEY_ID", "KEY")
    monkeypatch.setenv("APNS_PRIVATE_KEY", "PRIVATE")
    return TestClient(app)


def _register_controller(client: TestClient, private_key: ec.EllipticCurvePrivateKey):
    return client.post(
        "/v1/ember/controller-bootstraps",
        headers={"Authorization": "Bearer test-token"},
        json={
            "controllerId": CONTROLLER_ID,
            "tagId": TAG_ID,
            "publicKey": _public_key(private_key),
            "hardwareModel": "oelo_esp32",
            "attestation": "retrofit",
        },
    )


def _begin(client: TestClient, client_key: ec.EllipticCurvePrivateKey):
    return client.post(
        "/v1/ember/enrollment-challenges",
        json={
            "controllerId": CONTROLLER_ID,
            "tagId": TAG_ID,
            "proofMethod": "home_key_ble",
            "clientPublicKey": _public_key(client_key),
        },
    )


def _begin_retrofit(
    client: TestClient,
    client_key: ec.EllipticCurvePrivateKey,
    controller_key: ec.EllipticCurvePrivateKey,
):
    return client.post(
        "/v1/ember/enrollment-challenges",
        json={
            "controllerId": CONTROLLER_ID,
            "tagId": TAG_ID,
            "proofMethod": "home_key_ble",
            "clientPublicKey": _public_key(client_key),
            "controllerPublicKey": _public_key(controller_key),
            "hardwareModel": "oelo_esp32",
        },
    )


def _complete(
    client: TestClient,
    controller_key: ec.EllipticCurvePrivateKey,
    client_key: ec.EllipticCurvePrivateKey,
    challenge: dict,
    name: str = "Will's iPhone",
):
    message = enrollment_message(
        challenge["proofMethod"],
        challenge["challengeId"],
        CONTROLLER_ID,
        TAG_ID,
        key_thumbprint(_public_key(client_key)),
        challenge["serverNonce"],
    )
    return client.post(
        f"/v1/ember/enrollment-challenges/{challenge['challengeId']}/complete",
        json={
            "controllerSignature": _sign(controller_key, message),
            "clientName": name,
        },
    )


def test_bootstrap_is_admin_only_and_idempotent(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        unauthorized = client.post("/v1/ember/controller-bootstraps", json={})
        first = _register_controller(client, controller_key)
        second = _register_controller(client, controller_key)

    assert unauthorized.status_code == 401
    assert first.status_code == 200
    assert first.json()["created"] is True
    assert second.status_code == 200
    assert second.json()["created"] is False


def test_first_approval_creates_installation_and_replay_fails(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, controller_key).status_code == 200
        challenge_response = _begin(client, client_key)
        assert challenge_response.status_code == 200
        challenge = challenge_response.json()

        completed = _complete(client, controller_key, client_key, challenge)
        replay = _complete(client, controller_key, client_key, challenge)

    assert completed.status_code == 200
    assert completed.json()["createdInstallation"] is True
    assert completed.json()["installationId"]
    assert completed.json()["memberId"]
    assert replay.status_code == 409


def test_claimed_controller_enrolls_another_client_in_same_installation(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    first_client_key = ec.generate_private_key(ec.SECP256R1())
    second_client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, controller_key).status_code == 200
        first_challenge = _begin(client, first_client_key).json()
        first = _complete(client, controller_key, first_client_key, first_challenge).json()

        second_challenge = _begin(client, second_client_key).json()
        second_response = _complete(
            client,
            controller_key,
            second_client_key,
            second_challenge,
            "Kitchen iPad",
        )

    assert second_response.status_code == 200
    second = second_response.json()
    assert second["createdInstallation"] is False
    assert second["installationId"] == first["installationId"]
    assert second["memberId"] != first["memberId"]


def test_tampered_signature_and_expired_challenge_fail(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, controller_key).status_code == 200

        challenge = _begin(client, client_key).json()
        invalid = _complete(client, wrong_key, client_key, challenge)

        expired_challenge = _begin(client, client_key).json()
        with connect() as conn:
            conn.execute(
                "UPDATE ember_enrollment_challenges SET expires_at = ? WHERE id = ?",
                (
                    (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                    expired_challenge["challengeId"],
                ),
            )
            conn.commit()
        expired = _complete(client, controller_key, client_key, expired_challenge)

    assert invalid.status_code == 403
    assert expired.status_code == 410


def test_unknown_controller_does_not_issue_a_challenge(monkeypatch, tmp_path):
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        response = _begin(client, client_key)

    assert response.status_code == 404


def test_retrofit_controller_is_registered_only_after_valid_signed_completion(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        challenge_response = _begin_retrofit(client, client_key, controller_key)
        assert challenge_response.status_code == 200
        challenge = challenge_response.json()

        with connect() as conn:
            assert conn.execute(
                "SELECT 1 FROM ember_controller_bootstraps WHERE controller_id = ?",
                (CONTROLLER_ID,),
            ).fetchone() is None

        rejected = _complete(client, wrong_key, client_key, challenge)
        assert rejected.status_code == 403
        with connect() as conn:
            assert conn.execute(
                "SELECT 1 FROM ember_controller_bootstraps WHERE controller_id = ?",
                (CONTROLLER_ID,),
            ).fetchone() is None

        completed = _complete(client, controller_key, client_key, challenge)
        assert completed.status_code == 200
        assert completed.json()["createdInstallation"] is True
        with connect() as conn:
            assert conn.execute(
                "SELECT status FROM ember_controller_bootstraps WHERE controller_id = ?",
                (CONTROLLER_ID,),
            ).fetchone()["status"] == "active"


def test_retrofit_identity_conflict_is_rejected(monkeypatch, tmp_path):
    first_controller_key = ec.generate_private_key(ec.SECP256R1())
    second_controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        first_challenge = _begin_retrofit(client, client_key, first_controller_key).json()
        second_challenge = _begin_retrofit(client, client_key, second_controller_key).json()
        first = _complete(client, first_controller_key, client_key, first_challenge)
        conflict = _complete(client, second_controller_key, client_key, second_challenge)

    assert first.status_code == 200
    assert conflict.status_code == 409


def test_existing_challenge_schema_migrates_without_losing_identity(monkeypatch, tmp_path):
    database = tmp_path / "courier.db"
    monkeypatch.setenv("COURIER_DB_PATH", str(database))
    controller_key = ec.generate_private_key(ec.SECP256R1())
    public_key = _public_key(controller_key)
    with sqlite3.connect(database) as conn:
        conn.executescript(
            """
            CREATE TABLE ember_controller_bootstraps (
                controller_id TEXT PRIMARY KEY, tag_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL, hardware_model TEXT NOT NULL,
                attestation TEXT NOT NULL, key_version INTEGER NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE ember_enrollment_challenges (
                id TEXT PRIMARY KEY,
                controller_id TEXT NOT NULL REFERENCES ember_controller_bootstraps(controller_id),
                tag_id TEXT NOT NULL, proof_method TEXT NOT NULL,
                client_public_key TEXT NOT NULL, client_key_thumbprint TEXT NOT NULL,
                server_nonce TEXT NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, consumed_at TEXT
            );
            """
        )
        conn.execute(
            "INSERT INTO ember_controller_bootstraps VALUES (?, ?, ?, 'oelo_esp32', 'retrofit', 1, 'active', 'now', 'now')",
            (CONTROLLER_ID, TAG_ID, public_key),
        )
        conn.execute(
            "INSERT INTO ember_enrollment_challenges VALUES ('challenge', ?, ?, 'home_key_ble', ?, 'thumb', 'nonce', 'now', 'later', NULL)",
            (CONTROLLER_ID, TAG_ID, public_key),
        )
        conn.commit()

    init_db()

    with connect() as conn:
        migrated = conn.execute(
            "SELECT controller_public_key, hardware_model, retrofit FROM ember_enrollment_challenges WHERE id = 'challenge'"
        ).fetchone()
    assert dict(migrated) == {
        "controller_public_key": public_key,
        "hardware_model": "oelo_esp32",
        "retrofit": 0,
    }
