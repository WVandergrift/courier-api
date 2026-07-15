from __future__ import annotations

import html
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.apns import ApnsClient, ApnsSend, Environment
from app.auth import require_auth
from app.db import init_db, insert_event, list_events
from app.logging_config import configure_logging, log_fields, payload_summary, redact_token


logger = logging.getLogger("courier.api")


class PushRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    device_token: str = Field(alias="deviceToken", min_length=20)
    title: str | None = Field(default=None, max_length=178)
    body: str | None = Field(default=None, max_length=1024)
    data: dict[str, Any] = Field(default_factory=dict)
    environment: Environment = "sandbox"
    sandbox: bool | None = None
    apns_topic: str | None = Field(default=None, alias="apnsTopic")
    push_type: Literal["alert", "background", "voip", "complication", "fileprovider", "mdm", "liveactivity"] = Field(
        default="alert",
        alias="pushType",
    )
    sound: str | None = "default"
    badge: int | None = Field(default=None, ge=0)
    category: str | None = Field(default=None, max_length=64)
    thread_id: str | None = Field(default=None, alias="threadId", max_length=64)
    collapse_id: str | None = Field(default=None, alias="collapseId", max_length=64)
    expiration: int | None = Field(default=None, ge=0)

    @field_validator("device_token")
    @classmethod
    def normalize_device_token(cls, value: str) -> str:
        token = "".join(value.split())
        if not token:
            raise ValueError("deviceToken is required")
        return token

    @field_validator("data")
    @classmethod
    def data_must_be_object(cls, value: dict[str, Any]) -> dict[str, Any]:
        if "aps" in value:
            raise ValueError("data must not contain aps; use title/body/badge/sound fields instead")
        return value

    def selected_environment(self) -> Environment:
        if self.sandbox is not None:
            return "sandbox" if self.sandbox else "production"
        return self.environment

    def selected_topic(self) -> str:
        topic = (self.apns_topic or os.environ.get("DEFAULT_APNS_TOPIC") or "").strip()
        if not topic:
            raise HTTPException(status_code=400, detail="apnsTopic is required unless DEFAULT_APNS_TOPIC is configured.")
        return topic

    def payload(self) -> dict[str, Any]:
        aps: dict[str, Any] = {}
        alert: dict[str, str] = {}
        if self.title:
            alert["title"] = self.title
        if self.body:
            alert["body"] = self.body
        if alert:
            aps["alert"] = alert
        if self.badge is not None:
            aps["badge"] = self.badge
        if self.sound and self.push_type != "background":
            aps["sound"] = self.sound
        if self.push_type == "background":
            aps["content-available"] = 1
        # category names a UNNotificationCategory the app pre-registers; it is
        # what makes iOS render interactive action buttons on the notification.
        if self.category:
            aps["category"] = self.category
        # thread-id groups related pushes (e.g. one ticket) into a single thread.
        if self.thread_id:
            aps["thread-id"] = self.thread_id

        payload: dict[str, Any] = {"aps": aps}
        # Custom data goes under a top-level "body" key, NOT spread at the top
        # level. expo-notifications (the companion app's client) reads a remote
        # notification's content.data ONLY from userInfo["body"] — top-level
        # custom keys are dropped. This mirrors Expo's own push payload format.
        if self.data:
            payload["body"] = self.data
        return payload


class PushResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: int
    success: bool
    status: str
    environment: str
    apns_topic: str = Field(alias="apnsTopic")
    apns_id: str | None = Field(default=None, alias="apnsId")
    provider_status_code: int = Field(alias="providerStatusCode")
    retryable: bool
    invalid_token: bool = Field(alias="invalidToken")
    error_code: str | None = Field(default=None, alias="errorCode")
    error_message: str | None = Field(default=None, alias="errorMessage")
    latency_ms: int = Field(alias="latencyMs")


apns_client: ApnsClient | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global apns_client
    configure_logging()
    logger.info("service_starting")
    init_db()
    apns_client = ApnsClient.from_env()
    try:
        yield
    finally:
        if apns_client is not None:
            await apns_client.close()
        logger.info("service_stopped")


app = FastAPI(title="Courier Push API", version="0.2.0", lifespan=lifespan)

# Companion relay: the app<->daemon tunnel (WS agent + HTTP forward). See app/relay.py.
from app.relay import router as relay_router  # noqa: E402
from app.ember_identity import router as ember_identity_router  # noqa: E402

app.include_router(relay_router)
app.include_router(ember_identity_router)

EMBER_IOS_APP_ID = "3YWE9TBUAM.app.embercore"
EMBER_ANDROID_PACKAGE = "app.embercore"
EMBER_ANDROID_DEBUG_CERT_SHA256 = (
    "1A:19:65:54:6D:0A:F1:B3:26:F2:17:B2:CA:16:E4:3D:43:65:D0:09:"
    "44:D4:EB:6E:B2:6E:19:F6:9B:20:B6:4A"
)
EMBER_TAG_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid4())
    request.state.request_id = request_id
    started = time.monotonic()
    logger.info(
        "client_request_received",
        extra=log_fields(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=str(request.url.query),
            client_ip=request.client.host if request.client else None,
            content_length=request.headers.get("content-length"),
            content_type=request.headers.get("content-type"),
            user_agent=request.headers.get("user-agent"),
        ),
    )
    try:
        response = await call_next(request)
    except Exception:
        latency_ms = int((time.monotonic() - started) * 1000)
        logger.exception(
            "client_response_failed",
            extra=log_fields(
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                latency_ms=latency_ms,
            ),
        )
        raise

    latency_ms = int((time.monotonic() - started) * 1000)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "client_response_sent",
        extra=log_fields(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            content_length=response.headers.get("content-length"),
        ),
    )
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/.well-known/apple-app-site-association", include_in_schema=False)
async def ember_apple_app_site_association() -> JSONResponse:
    return JSONResponse(
        {
            "applinks": {
                "apps": [],
                "details": [
                    {
                        "appID": EMBER_IOS_APP_ID,
                        "paths": ["/ember/t/*"],
                    }
                ],
            }
        },
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/.well-known/assetlinks.json", include_in_schema=False)
async def ember_android_asset_links() -> JSONResponse:
    configured = os.environ.get("EMBER_ANDROID_CERT_SHA256", "")
    fingerprints = [EMBER_ANDROID_DEBUG_CERT_SHA256]
    fingerprints.extend(item.strip().upper() for item in configured.split(",") if item.strip())
    return JSONResponse(
        [
            {
                "relation": ["delegate_permission/common.handle_all_urls"],
                "target": {
                    "namespace": "android_app",
                    "package_name": EMBER_ANDROID_PACKAGE,
                    "sha256_cert_fingerprints": list(dict.fromkeys(fingerprints)),
                },
            }
        ],
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/ember/t/{tag_id}", response_class=HTMLResponse, include_in_schema=False)
async def ember_home_key_landing(tag_id: str) -> HTMLResponse:
    if not EMBER_TAG_ID_PATTERN.fullmatch(tag_id):
        raise HTTPException(status_code=404, detail="Home Key not found.")
    # The Home Key secret lives after `#` and is never part of this request.
    # Avoid reflecting even the public tag ID into the page or logs beyond the
    # normal request path.
    return HTMLResponse(
        (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Open Ember Home Key</title><style>body{font:18px system-ui;"
            "max-width:38rem;margin:12vh auto;padding:1.5rem;background:#0f1218;"
            "color:#f6f1e8}p{color:#c8c5bd;line-height:1.5}</style></head>"
            "<body><h1>Ember Home Key</h1><p>Install or open Ember on this device, "
            "then tap the Home Key again to securely set up or join this Home.</p>"
            "</body></html>"
        ),
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.post("/v1/push/ios", response_model=PushResponse, dependencies=[Depends(require_auth)])
async def send_ios_push(request: Request, push_request: PushRequest) -> PushResponse:
    if apns_client is None:
        raise HTTPException(status_code=503, detail="APNs client is not initialized.")

    request_id = getattr(request.state, "request_id", None)
    environment = push_request.selected_environment()
    topic = push_request.selected_topic()
    payload = push_request.payload()
    logger.info(
        "push_request_accepted",
        extra=log_fields(
            request_id=request_id,
            environment=environment,
            topic=topic,
            push_type=push_request.push_type,
            collapse_id=push_request.collapse_id,
            expiration=push_request.expiration,
            device_token=redact_token(push_request.device_token),
            payload=payload_summary(payload),
        ),
    )
    started = time.monotonic()
    result = await apns_client.send(
        ApnsSend(
            device_token=push_request.device_token,
            topic=topic,
            environment=environment,
            payload=payload,
            push_type=push_request.push_type,
            collapse_id=push_request.collapse_id,
            expiration=push_request.expiration,
            request_id=request_id,
        )
    )
    latency_ms = int((time.monotonic() - started) * 1000)
    status = "sent" if result.success else "failed"
    event_id = insert_event(
        {
            "environment": environment,
            "apns_topic": topic,
            "device_token": push_request.device_token,
            "title": push_request.title,
            "body": push_request.body,
            "payload": payload,
            "status": status,
            "provider_status_code": result.status_code,
            "apns_id": result.apns_id,
            "error_code": result.error_code,
            "error_message": result.error_message,
            "retryable": int(result.retryable),
            "invalid_token": int(result.invalid_token),
            "latency_ms": latency_ms,
        }
    )
    response = PushResponse(
        id=event_id,
        success=result.success,
        status=status,
        environment=environment,
        apnsTopic=topic,
        apnsId=result.apns_id,
        providerStatusCode=result.status_code,
        retryable=result.retryable,
        invalidToken=result.invalid_token,
        errorCode=result.error_code,
        errorMessage=result.error_message,
        latencyMs=latency_ms,
    )
    logger.info(
        "push_response_prepared",
        extra=log_fields(
            request_id=request_id,
            event_id=event_id,
            success=result.success,
            status=status,
            environment=environment,
            topic=topic,
            provider_status_code=result.status_code,
            apns_id=result.apns_id,
            retryable=result.retryable,
            invalid_token=result.invalid_token,
            error_code=result.error_code,
            latency_ms=latency_ms,
        ),
    )
    return response


@app.get("/v1/events", dependencies=[Depends(require_auth)])
async def events(limit: int = 100) -> dict[str, Any]:
    return {"events": list_events(limit)}


@app.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def dashboard() -> str:
    rows = list_events(100)
    body = "\n".join(_event_row(event) for event in rows) or '<tr><td colspan="10">No events yet.</td></tr>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Courier Push Events</title>
  <style>
    :root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; background: #f7f7f4; color: #1e2425; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px; }}
    header {{ display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
    h1 {{ font-size: 22px; margin: 0; font-weight: 650; }}
    a {{ color: #0f766e; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9dedb; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #e6e8e6; text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ background: #eef2ef; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
    .sent {{ color: #047857; font-weight: 650; }}
    .failed {{ color: #b42318; font-weight: 650; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #111615; color: #eef2ef; }}
      table {{ background: #19201f; border-color: #33413e; }}
      th {{ background: #202a28; }}
      th, td {{ border-bottom-color: #2a3634; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Courier Push Events</h1>
      <a href="/v1/events">JSON</a>
    </header>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Created</th><th>Status</th><th>Env</th><th>Topic</th><th>Token</th><th>Title</th><th>APNs</th><th>Error</th><th>Latency</th>
        </tr>
      </thead>
      <tbody>{body}</tbody>
    </table>
  </main>
</body>
</html>"""


def _event_row(event: dict[str, Any]) -> str:
    status = html.escape(str(event["status"]))
    return (
        "<tr>"
        f"<td>{event['id']}</td>"
        f"<td><code>{html.escape(event['created_at'])}</code></td>"
        f"<td class=\"{status}\">{status}</td>"
        f"<td>{html.escape(event['environment'])}</td>"
        f"<td><code>{html.escape(event['apns_topic'])}</code></td>"
        f"<td><code>...{html.escape(event['device_token_suffix'])}</code></td>"
        f"<td>{html.escape(event['title'] or '')}</td>"
        f"<td>{html.escape(str(event['provider_status_code'] or ''))}<br><code>{html.escape(event['apns_id'] or '')}</code></td>"
        f"<td>{html.escape(event['error_code'] or '')}</td>"
        f"<td>{event['latency_ms']}ms</td>"
        "</tr>"
    )
