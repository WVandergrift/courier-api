from __future__ import annotations

import base64
import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from app.db import connect, init_db
from app.ember_identity import (
    controller_add_grant_message,
    enrollment_message,
    key_thumbprint,
)
from app.ember_recovery import recovery_message
from app.main import app


CONTROLLER_ID = "AABBCCDDEEFF"
TAG_ID = "tag_01J2NFCEMBERCORE"
SECOND_CONTROLLER_ID = "112233445566"
SECOND_TAG_ID = "controller_112233445566"


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


def _create_and_authorize_grant(
    client: TestClient,
    authorizer_key: ec.EllipticCurvePrivateKey,
    installation_id: str,
    member_id: str,
    controller_key: ec.EllipticCurvePrivateKey,
    controller_id: str,
    tag_id: str,
    *,
    signature_key: ec.EllipticCurvePrivateKey | None = None,
):
    controller_public_key = _public_key(controller_key)
    response = client.post(
        "/v1/ember/controller-add-grants",
        json={
            "installationId": installation_id,
            "authorizerMemberId": member_id,
            "controllerId": controller_id,
            "controllerPublicKey": controller_public_key,
            "tagId": tag_id,
            "hardwareModel": "oelo_esp32",
        },
    )
    assert response.status_code == 200
    grant = response.json()
    message = controller_add_grant_message(
        grant["grantId"],
        installation_id,
        member_id,
        controller_id,
        key_thumbprint(controller_public_key),
        tag_id,
        "oelo_esp32",
        key_thumbprint(_public_key(authorizer_key)),
        grant["serverNonce"],
        grant["expiresAt"],
    )
    authorized = client.post(
        f"/v1/ember/controller-add-grants/{grant['grantId']}/authorize",
        json={"clientSignature": _sign(signature_key or authorizer_key, message)},
    )
    return grant, authorized


def _complete_identity(
    client: TestClient,
    controller_key: ec.EllipticCurvePrivateKey,
    client_key: ec.EllipticCurvePrivateKey,
    challenge: dict,
    controller_id: str,
    tag_id: str,
):
    message = enrollment_message(
        challenge["proofMethod"],
        challenge["challengeId"],
        controller_id,
        tag_id,
        key_thumbprint(_public_key(client_key)),
        challenge["serverNonce"],
    )
    return client.post(
        f"/v1/ember/enrollment-challenges/{challenge['challengeId']}/complete",
        json={
            "controllerSignature": _sign(controller_key, message),
            "clientName": "Will's iPhone",
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


def test_controller_add_grant_adds_exact_controller_to_existing_installation(monkeypatch, tmp_path):
    first_controller_key = ec.generate_private_key(ec.SECP256R1())
    second_controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, first_controller_key).status_code == 200
        first_challenge = _begin(client, client_key).json()
        first = _complete(client, first_controller_key, client_key, first_challenge).json()

        grant, authorized = _create_and_authorize_grant(
            client,
            client_key,
            first["installationId"],
            first["memberId"],
            second_controller_key,
            SECOND_CONTROLLER_ID,
            SECOND_TAG_ID,
        )
        assert authorized.status_code == 200

        challenge_response = client.post(
            "/v1/ember/enrollment-challenges",
            json={
                "controllerId": SECOND_CONTROLLER_ID,
                "tagId": SECOND_TAG_ID,
                "proofMethod": "controller_button",
                "clientPublicKey": _public_key(client_key),
                "controllerPublicKey": _public_key(second_controller_key),
                "hardwareModel": "oelo_esp32",
                "controllerAddGrantId": grant["grantId"],
            },
        )
        assert challenge_response.status_code == 200
        completed = _complete_identity(
            client,
            second_controller_key,
            client_key,
            challenge_response.json(),
            SECOND_CONTROLLER_ID,
            SECOND_TAG_ID,
        )
        replay = client.post(
            "/v1/ember/enrollment-challenges",
            json={
                "controllerId": SECOND_CONTROLLER_ID,
                "tagId": SECOND_TAG_ID,
                "proofMethod": "controller_button",
                "clientPublicKey": _public_key(client_key),
                "controllerAddGrantId": grant["grantId"],
            },
        )

    assert completed.status_code == 200
    result = completed.json()
    assert result["installationId"] == first["installationId"]
    assert result["memberId"] == first["memberId"]
    assert result["createdInstallation"] is False
    assert replay.status_code == 403


def test_button_grant_recovers_factory_reset_controller_into_same_installation(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    reset_tag_id = f"controller_{CONTROLLER_ID}"
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, controller_key).status_code == 200
        first = _complete(
            client, controller_key, client_key, _begin(client, client_key).json()
        ).json()

        grant, authorized = _create_and_authorize_grant(
            client,
            client_key,
            first["installationId"],
            first["memberId"],
            controller_key,
            CONTROLLER_ID,
            reset_tag_id,
        )
        assert authorized.status_code == 200
        challenge = client.post(
            "/v1/ember/enrollment-challenges",
            json={
                "controllerId": CONTROLLER_ID,
                "tagId": reset_tag_id,
                "proofMethod": "controller_button",
                "clientPublicKey": _public_key(client_key),
                "controllerPublicKey": _public_key(controller_key),
                "hardwareModel": "oelo_esp32",
                "controllerAddGrantId": grant["grantId"],
            },
        )
        assert challenge.status_code == 200
        recovered = _complete_identity(
            client,
            controller_key,
            client_key,
            challenge.json(),
            CONTROLLER_ID,
            reset_tag_id,
        )

    assert recovered.status_code == 200
    result = recovered.json()
    assert result["installationId"] == first["installationId"]
    assert result["controllerMemberId"] == first["controllerMemberId"]
    assert result["memberId"] == first["memberId"]
    assert result["createdInstallation"] is False


def test_controller_add_grant_rejects_wrong_client_signature_and_identity_swap(monkeypatch, tmp_path):
    first_controller_key = ec.generate_private_key(ec.SECP256R1())
    second_controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    wrong_client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, first_controller_key).status_code == 200
        first_challenge = _begin(client, client_key).json()
        first = _complete(client, first_controller_key, client_key, first_challenge).json()

        grant, rejected = _create_and_authorize_grant(
            client,
            client_key,
            first["installationId"],
            first["memberId"],
            second_controller_key,
            SECOND_CONTROLLER_ID,
            SECOND_TAG_ID,
            signature_key=wrong_client_key,
        )
        assert rejected.status_code == 403

        grant_row = connect().execute(
            "SELECT * FROM ember_controller_add_grants WHERE id = ?", (grant["grantId"],)
        ).fetchone()
        message = controller_add_grant_message(
            grant_row["id"], grant_row["installation_id"],
            grant_row["authorizer_member_id"], grant_row["controller_id"],
            grant_row["controller_key_thumbprint"], grant_row["tag_id"],
            grant_row["hardware_model"], grant_row["client_key_thumbprint"],
            grant_row["server_nonce"], grant_row["expires_at"],
        )
        approved = client.post(
            f"/v1/ember/controller-add-grants/{grant['grantId']}/authorize",
            json={"clientSignature": _sign(client_key, message)},
        )
        assert approved.status_code == 200

        swapped = client.post(
            "/v1/ember/enrollment-challenges",
            json={
                "controllerId": SECOND_CONTROLLER_ID,
                "tagId": "controller_000000000000",
                "proofMethod": "controller_button",
                "clientPublicKey": _public_key(client_key),
                "controllerPublicKey": _public_key(second_controller_key),
                "hardwareModel": "oelo_esp32",
                "controllerAddGrantId": grant["grantId"],
            },
        )

    assert swapped.status_code == 409


def test_controller_add_grant_rechecks_expiry_revocation_and_admin_capability(monkeypatch, tmp_path):
    first_controller_key = ec.generate_private_key(ec.SECP256R1())
    second_controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, first_controller_key).status_code == 200
        first = _complete(
            client, first_controller_key, client_key, _begin(client, client_key).json()
        ).json()
        request = {
            "installationId": first["installationId"],
            "authorizerMemberId": first["memberId"],
            "controllerId": SECOND_CONTROLLER_ID,
            "controllerPublicKey": _public_key(second_controller_key),
            "tagId": SECOND_TAG_ID,
            "hardwareModel": "oelo_esp32",
        }

        expired_grant = client.post("/v1/ember/controller-add-grants", json=request).json()
        with connect() as conn:
            conn.execute(
                "UPDATE ember_controller_add_grants SET expires_at = ? WHERE id = ?",
                (_iso_for_test(datetime.now(UTC) - timedelta(seconds=1)), expired_grant["grantId"]),
            )
            conn.commit()
        expired = client.post(
            f"/v1/ember/controller-add-grants/{expired_grant['grantId']}/authorize",
            json={"clientSignature": _b64u(bytes(64))},
        )
        assert expired.status_code == 410

        active_grant = client.post("/v1/ember/controller-add-grants", json=request).json()
        with connect() as conn:
            conn.execute(
                "UPDATE ember_members SET revoked_at = ? WHERE id = ?",
                (_iso_for_test(datetime.now(UTC)), first["memberId"]),
            )
            conn.commit()
        revoked = client.post(
            f"/v1/ember/controller-add-grants/{active_grant['grantId']}/authorize",
            json={"clientSignature": _b64u(bytes(64))},
        )
        assert revoked.status_code == 403

        with connect() as conn:
            conn.execute(
                "UPDATE ember_members SET revoked_at = NULL, capabilities_json = '[]' WHERE id = ?",
                (first["memberId"],),
            )
            conn.commit()
        not_admin = client.post("/v1/ember/controller-add-grants", json=request)

    assert not_admin.status_code == 403


def _iso_for_test(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


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


def test_encrypted_recovery_backup_round_trip_and_kind_isolation(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    payload = _b64u(b'{"ciphertext":"opaque","deviceWrap":"opaque"}')
    digest = hashlib.sha256(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).hexdigest()
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, controller_key).status_code == 200
        enrollment = _complete(
            client, controller_key, client_key, _begin(client, client_key).json()
        ).json()
        backup_id = "22222222-2222-4222-8222-222222222222"
        requested_at = _iso_for_test(datetime.now(UTC))
        upload = client.post(
            "/v1/ember/recovery-backups",
            json={
                "installationId": enrollment["installationId"],
                "memberId": enrollment["memberId"],
                "controllerId": CONTROLLER_ID,
                "backupId": backup_id,
                "backupKind": "oelo_configuration",
                "hardwareProfile": "oelo_esp32",
                "formatVersion": 1,
                "payload": payload,
                "payloadDigest": digest,
                "capturedAt": requested_at,
                "requestedAt": requested_at,
                "clientSignature": _sign(
                    client_key,
                    recovery_message(
                        "upload", enrollment["installationId"], enrollment["memberId"],
                        CONTROLLER_ID,
                        f"{digest}:oelo_configuration:{backup_id}:{requested_at}",
                        requested_at,
                    ),
                ),
            },
        )
        query_at = _iso_for_test(datetime.now(UTC))
        downloaded = client.post(
            "/v1/ember/recovery-backups/latest",
            json={
                "installationId": enrollment["installationId"],
                "memberId": enrollment["memberId"],
                "controllerId": CONTROLLER_ID,
                "backupKind": "oelo_configuration",
                "requestedAt": query_at,
                "clientSignature": _sign(
                    client_key,
                    recovery_message(
                        "latest", enrollment["installationId"], enrollment["memberId"],
                        CONTROLLER_ID, "latest:oelo_configuration", query_at,
                    ),
                ),
            },
        )
        missing_kind = client.post(
            "/v1/ember/recovery-backups/latest",
            json={
                "installationId": enrollment["installationId"],
                "memberId": enrollment["memberId"],
                "controllerId": CONTROLLER_ID,
                "backupKind": "ember_rollback",
                "requestedAt": query_at,
                "clientSignature": _sign(
                    client_key,
                    recovery_message(
                        "latest", enrollment["installationId"], enrollment["memberId"],
                        CONTROLLER_ID, "latest:ember_rollback", query_at,
                    ),
                ),
            },
        )

    assert upload.status_code == 200
    assert upload.json()["payload"] is None
    assert downloaded.status_code == 200
    assert downloaded.json()["payload"] == payload
    assert downloaded.json()["payloadDigest"] == digest
    assert missing_kind.status_code == 404


def test_recovery_backup_rejects_tampering_and_stale_authorization(monkeypatch, tmp_path):
    controller_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    with _client(monkeypatch, tmp_path) as client:
        assert _register_controller(client, controller_key).status_code == 200
        enrollment = _complete(
            client, controller_key, client_key, _begin(client, client_key).json()
        ).json()
        stale_at = _iso_for_test(datetime.now(UTC) - timedelta(minutes=6))
        response = client.post(
            "/v1/ember/recovery-backups/latest",
            json={
                "installationId": enrollment["installationId"],
                "memberId": enrollment["memberId"],
                "controllerId": CONTROLLER_ID,
                "backupKind": "oelo_configuration",
                "requestedAt": stale_at,
                "clientSignature": _b64u(bytes(64)),
            },
        )
        fresh_at = _iso_for_test(datetime.now(UTC))
        tampered = client.post(
            "/v1/ember/recovery-backups/latest",
            json={
                "installationId": enrollment["installationId"],
                "memberId": enrollment["memberId"],
                "controllerId": CONTROLLER_ID,
                "backupKind": "oelo_configuration",
                "requestedAt": fresh_at,
                "clientSignature": _b64u(bytes(64)),
            },
        )

    assert response.status_code == 422
    assert tampered.status_code == 403
