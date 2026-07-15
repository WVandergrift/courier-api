from __future__ import annotations

import base64
import hmac
import os

from fastapi import Header, HTTPException


def configured_api_token() -> str:
    token = os.environ.get("COURIER_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError("COURIER_API_TOKEN is required.")
    return token


def _basic_password(value: str) -> str | None:
    try:
        scheme, encoded = value.split(" ", 1)
    except ValueError:
        return None
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(encoded.strip()).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    return decoded.split(":", 1)[1]


def _bearer_token(value: str) -> str | None:
    try:
        scheme, token = value.split(" ", 1)
    except ValueError:
        return None
    if scheme.lower() != "bearer":
        return None
    return token.strip()


def require_auth(authorization: str | None = Header(default=None)) -> None:
    expected = configured_api_token()
    provided = ""
    if authorization:
        provided = _bearer_token(authorization) or _basic_password(authorization) or ""
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="Courier"'},
        )
