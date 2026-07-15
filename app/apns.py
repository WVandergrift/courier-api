from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
import jwt

from app.logging_config import log_fields, payload_summary, redact_token


APNS_TOKEN_TTL = timedelta(minutes=50)
APNS_HOSTS = {
    "sandbox": "https://api.sandbox.push.apple.com",
    "production": "https://api.push.apple.com",
}
INVALID_TOKEN_REASONS = {"BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"}
RETRYABLE_STATUS_CODES = {429, 500, 503}
logger = logging.getLogger("courier.apns")


Environment = Literal["sandbox", "production"]


@dataclass(frozen=True)
class ApnsSend:
    device_token: str
    topic: str
    environment: Environment
    payload: dict[str, Any]
    push_type: str = "alert"
    priority: int | None = None
    collapse_id: str | None = None
    expiration: int | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class ApnsResult:
    success: bool
    status_code: int
    apns_id: str | None = None
    retryable: bool = False
    invalid_token: bool = False
    error_code: str | None = None
    error_message: str | None = None


class ApnsClient:
    def __init__(
        self,
        *,
        team_id: str,
        key_id: str,
        private_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.team_id = team_id
        self.key_id = key_id
        self.private_key = private_key
        self._client = client or httpx.AsyncClient(http2=True, timeout=10.0)
        self._owns_client = client is None
        self._cached_token: tuple[str, datetime] | None = None

    @classmethod
    def from_env(cls) -> "ApnsClient":
        team_id = os.environ.get("APNS_TEAM_ID", "").strip()
        key_id = os.environ.get("APNS_KEY_ID", "").strip()
        private_key = _load_private_key()
        missing = [name for name, value in [("APNS_TEAM_ID", team_id), ("APNS_KEY_ID", key_id)] if not value]
        if missing:
            raise RuntimeError(f"Missing APNs settings: {', '.join(missing)}")
        return cls(team_id=team_id, key_id=key_id, private_key=private_key)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def send(self, request: ApnsSend) -> ApnsResult:
        url = f"{APNS_HOSTS[request.environment]}/3/device/{request.device_token}"
        headers = self._headers(request)
        logger.info(
            "apns_request_sent",
            extra=log_fields(
                request_id=request.request_id,
                environment=request.environment,
                topic=request.topic,
                push_type=request.push_type,
                priority=headers.get("apns-priority"),
                collapse_id=request.collapse_id,
                expiration=request.expiration,
                device_token=redact_token(request.device_token),
                payload=payload_summary(request.payload),
            ),
        )
        try:
            response = await self._client.post(url, headers=headers, json=request.payload)
        except Exception:
            logger.exception(
                "apns_request_failed",
                extra=log_fields(
                    request_id=request.request_id,
                    environment=request.environment,
                    topic=request.topic,
                    push_type=request.push_type,
                    device_token=redact_token(request.device_token),
                ),
            )
            raise
        apns_id = response.headers.get("apns-id")
        if response.status_code == 200:
            logger.info(
                "apns_response_received",
                extra=log_fields(
                    request_id=request.request_id,
                    environment=request.environment,
                    topic=request.topic,
                    status_code=response.status_code,
                    apns_id=apns_id,
                    success=True,
                    retryable=False,
                    invalid_token=False,
                ),
            )
            return ApnsResult(success=True, status_code=200, apns_id=apns_id)

        reason = _extract_reason(response)
        logger.info(
            "apns_response_received",
            extra=log_fields(
                request_id=request.request_id,
                environment=request.environment,
                topic=request.topic,
                status_code=response.status_code,
                apns_id=apns_id,
                success=False,
                retryable=response.status_code in RETRYABLE_STATUS_CODES,
                invalid_token=reason in INVALID_TOKEN_REASONS,
                error_code=reason,
            ),
        )
        return ApnsResult(
            success=False,
            status_code=response.status_code,
            apns_id=apns_id,
            retryable=response.status_code in RETRYABLE_STATUS_CODES,
            invalid_token=reason in INVALID_TOKEN_REASONS,
            error_code=reason,
            error_message=reason,
        )

    def _headers(self, request: ApnsSend) -> dict[str, str]:
        headers = {
            "authorization": f"bearer {self._authorization_token()}",
            "apns-topic": request.topic,
            "apns-push-type": request.push_type,
            "apns-priority": str(request.priority or (5 if request.push_type == "background" else 10)),
        }
        if request.collapse_id:
            headers["apns-collapse-id"] = request.collapse_id
        if request.expiration is not None:
            headers["apns-expiration"] = str(request.expiration)
        return headers

    def _authorization_token(self) -> str:
        now = datetime.now(UTC)
        if self._cached_token is not None:
            token, issued_at = self._cached_token
            if now - issued_at < APNS_TOKEN_TTL:
                return token

        token = jwt.encode(
            {"iss": self.team_id, "iat": int(now.timestamp())},
            self.private_key,
            algorithm="ES256",
            headers={"kid": self.key_id},
        )
        self._cached_token = (token, now)
        return token


def _load_private_key() -> str:
    raw = os.environ.get("APNS_PRIVATE_KEY", "").strip()
    if raw:
        return raw.replace("\\n", "\n")

    encoded = os.environ.get("APNS_PRIVATE_KEY_BASE64", "").strip()
    if encoded:
        return base64.b64decode(encoded).decode("utf-8")

    path = os.environ.get("APNS_PRIVATE_KEY_PATH", "").strip()
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    raise RuntimeError("One of APNS_PRIVATE_KEY, APNS_PRIVATE_KEY_BASE64, or APNS_PRIVATE_KEY_PATH is required.")


def _extract_reason(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except json.JSONDecodeError:
        return response.text[:200] or "APNsError"
    if isinstance(payload, dict):
        reason = payload.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    return "APNsError"
