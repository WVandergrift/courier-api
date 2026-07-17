from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def database_path() -> str:
    return os.environ.get("COURIER_DB_PATH", "/data/courier.db")


def connect() -> sqlite3.Connection:
    path = Path(database_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS push_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                environment TEXT NOT NULL,
                apns_topic TEXT NOT NULL,
                device_token_hash TEXT NOT NULL,
                device_token_suffix TEXT NOT NULL,
                title TEXT,
                body TEXT,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_status_code INTEGER,
                apns_id TEXT,
                error_code TEXT,
                error_message TEXT,
                retryable INTEGER NOT NULL DEFAULT 0,
                invalid_token INTEGER NOT NULL DEFAULT 0,
                latency_ms INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_push_events_created_at ON push_events(created_at DESC)")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ember_controller_bootstraps (
                controller_id TEXT PRIMARY KEY,
                tag_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                hardware_model TEXT NOT NULL,
                attestation TEXT NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ember_installations (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'active',
                revision INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ember_members (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                key_thumbprint TEXT NOT NULL,
                display_name TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                revoked_at TEXT,
                UNIQUE (installation_id, kind, subject_id),
                UNIQUE (installation_id, key_thumbprint)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_ember_controller_members_subject
                ON ember_members(subject_id) WHERE kind = 'controller';
            CREATE INDEX IF NOT EXISTS idx_ember_members_installation
                ON ember_members(installation_id, created_at);

            CREATE TABLE IF NOT EXISTS ember_controller_add_grants (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                authorizer_member_id TEXT NOT NULL REFERENCES ember_members(id),
                controller_id TEXT NOT NULL,
                controller_public_key TEXT NOT NULL,
                controller_key_thumbprint TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                hardware_model TEXT NOT NULL,
                client_key_thumbprint TEXT NOT NULL,
                server_nonce TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                authorized_at TEXT,
                consumed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_ember_controller_add_grants_installation
                ON ember_controller_add_grants(installation_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_ember_controller_add_grants_controller
                ON ember_controller_add_grants(controller_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS ember_enrollment_challenges (
                id TEXT PRIMARY KEY,
                controller_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                proof_method TEXT NOT NULL,
                client_public_key TEXT NOT NULL,
                client_key_thumbprint TEXT NOT NULL,
                controller_public_key TEXT NOT NULL,
                hardware_model TEXT NOT NULL,
                retrofit INTEGER NOT NULL DEFAULT 0,
                controller_add_grant_id TEXT REFERENCES ember_controller_add_grants(id),
                server_nonce TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_ember_enrollment_challenges_controller
                ON ember_enrollment_challenges(controller_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS ember_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                installation_id TEXT,
                actor_member_id TEXT,
                event_type TEXT NOT NULL,
                subject_id TEXT,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ember_audit_installation
                ON ember_audit_events(installation_id, id DESC);

            CREATE TABLE IF NOT EXISTS ember_recovery_backups (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                controller_id TEXT NOT NULL,
                backup_kind TEXT NOT NULL,
                hardware_profile TEXT NOT NULL,
                format_version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ember_recovery_backups_controller
                ON ember_recovery_backups(installation_id, controller_id, backup_kind, created_at DESC);

            CREATE TABLE IF NOT EXISTS ember_join_requests (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                controller_id TEXT NOT NULL,
                candidate_public_key TEXT NOT NULL,
                candidate_key_thumbprint TEXT NOT NULL,
                candidate_name TEXT NOT NULL,
                server_nonce TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT,
                approving_member_id TEXT REFERENCES ember_members(id),
                member_id TEXT REFERENCES ember_members(id)
            );

            CREATE INDEX IF NOT EXISTS idx_ember_join_requests_installation
                ON ember_join_requests(installation_id, status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_ember_join_requests_candidate
                ON ember_join_requests(candidate_key_thumbprint, created_at DESC);

            CREATE TABLE IF NOT EXISTS ember_member_push_tokens (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                member_id TEXT NOT NULL REFERENCES ember_members(id),
                platform TEXT NOT NULL,
                environment TEXT NOT NULL,
                app_topic TEXT NOT NULL,
                token_ciphertext TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_validated_at TEXT NOT NULL,
                revoked_at TEXT,
                UNIQUE (member_id, platform, environment, app_topic)
            );

            CREATE INDEX IF NOT EXISTS idx_ember_member_push_tokens_installation
                ON ember_member_push_tokens(installation_id, revoked_at, updated_at DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ember_member_push_tokens_active_token
                ON ember_member_push_tokens(environment, app_topic, token_hash)
                WHERE revoked_at IS NULL;

            CREATE TABLE IF NOT EXISTS ember_client_invitations (
                id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                authorizer_member_id TEXT NOT NULL REFERENCES ember_members(id),
                secret_hash TEXT NOT NULL,
                server_nonce TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                authorized_at TEXT,
                consumed_at TEXT,
                member_id TEXT REFERENCES ember_members(id)
            );

            CREATE INDEX IF NOT EXISTS idx_ember_client_invitations_installation
                ON ember_client_invitations(installation_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS ember_installation_documents (
                installation_id TEXT NOT NULL REFERENCES ember_installations(id),
                document_key TEXT NOT NULL,
                revision INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                payload BLOB NOT NULL,
                payload_digest TEXT NOT NULL,
                updated_by_member_id TEXT NOT NULL REFERENCES ember_members(id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (installation_id, document_key)
            );

            CREATE INDEX IF NOT EXISTS idx_ember_installation_documents_updated
                ON ember_installation_documents(installation_id, updated_at DESC);
            """
        )
        challenge_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(ember_enrollment_challenges)")
        }
        if "proof_method" not in challenge_columns:
            conn.execute(
                """
                ALTER TABLE ember_enrollment_challenges
                ADD COLUMN proof_method TEXT NOT NULL DEFAULT 'home_key_ble'
                """
            )
        if not {"controller_public_key", "hardware_model", "retrofit"}.issubset(challenge_columns):
            # Older deployments required a bootstrap row before a challenge
            # could exist. Rebuild the table so a retrofit controller can
            # propose its identity only inside a short-lived challenge. The
            # bootstrap is created after that key signs the challenge.
            conn.execute("DROP INDEX IF EXISTS idx_ember_enrollment_challenges_controller")
            conn.execute("ALTER TABLE ember_enrollment_challenges RENAME TO ember_enrollment_challenges_legacy")
            conn.execute(
                """
                CREATE TABLE ember_enrollment_challenges (
                    id TEXT PRIMARY KEY,
                    controller_id TEXT NOT NULL,
                    tag_id TEXT NOT NULL,
                    proof_method TEXT NOT NULL,
                    client_public_key TEXT NOT NULL,
                    client_key_thumbprint TEXT NOT NULL,
                    controller_public_key TEXT NOT NULL,
                    hardware_model TEXT NOT NULL,
                    retrofit INTEGER NOT NULL DEFAULT 0,
                    controller_add_grant_id TEXT REFERENCES ember_controller_add_grants(id),
                    server_nonce TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO ember_enrollment_challenges
                    (id, controller_id, tag_id, proof_method, client_public_key,
                     client_key_thumbprint, controller_public_key, hardware_model,
                     retrofit, controller_add_grant_id, server_nonce, created_at,
                     expires_at, consumed_at)
                SELECT c.id, c.controller_id, c.tag_id, c.proof_method,
                       c.client_public_key, c.client_key_thumbprint, b.public_key,
                       b.hardware_model, 0, NULL, c.server_nonce, c.created_at,
                       c.expires_at, c.consumed_at
                FROM ember_enrollment_challenges_legacy c
                JOIN ember_controller_bootstraps b
                  ON b.controller_id = c.controller_id
                """
            )
            conn.execute("DROP TABLE ember_enrollment_challenges_legacy")
            conn.execute(
                """
                CREATE INDEX idx_ember_enrollment_challenges_controller
                    ON ember_enrollment_challenges(controller_id, created_at DESC)
                """
            )
        else:
            challenge_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(ember_enrollment_challenges)")
            }
            if "controller_add_grant_id" not in challenge_columns:
                conn.execute(
                    """
                    ALTER TABLE ember_enrollment_challenges
                    ADD COLUMN controller_add_grant_id TEXT
                        REFERENCES ember_controller_add_grants(id)
                    """
                )
        conn.commit()


def insert_event(event: dict[str, Any]) -> int:
    token = event.pop("device_token")
    event["created_at"] = datetime.now(UTC).isoformat()
    event["device_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    event["device_token_suffix"] = token[-8:]
    event["payload_json"] = json.dumps(event["payload"], ensure_ascii=True, sort_keys=True)
    del event["payload"]

    columns = list(event.keys())
    placeholders = ", ".join(["?"] * len(columns))
    with connect() as conn:
        cursor = conn.execute(
            f"INSERT INTO push_events ({', '.join(columns)}) VALUES ({placeholders})",
            [event[column] for column in columns],
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_events(limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM push_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        item["retryable"] = bool(item["retryable"])
        item["invalid_token"] = bool(item["invalid_token"])
        events.append(item)
    return events
