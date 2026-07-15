from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in getattr(record, "fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def configure_logging() -> None:
    level_name = os.environ.get("COURIER_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    logging.getLogger("httpx").setLevel(os.environ.get("COURIER_HTTPX_LOG_LEVEL", "WARNING").upper())


def log_fields(**fields: Any) -> dict[str, Any]:
    return {"fields": fields}


def redact_token(token: str) -> dict[str, str | int]:
    return {
        "hash": hashlib.sha256(token.encode("utf-8")).hexdigest()[:16],
        "suffix": token[-8:],
        "length": len(token),
    }


def payload_summary(payload: dict[str, Any]) -> dict[str, Any]:
    aps = payload.get("aps")
    aps_keys = sorted(aps.keys()) if isinstance(aps, dict) else []
    data_keys = sorted(key for key in payload.keys() if key != "aps")
    alert = aps.get("alert") if isinstance(aps, dict) else None
    alert_keys = sorted(alert.keys()) if isinstance(alert, dict) else []
    return {
        "aps_keys": aps_keys,
        "alert_keys": alert_keys,
        "data_keys": data_keys,
        "payload_bytes": len(json.dumps(payload, ensure_ascii=True, separators=(",", ":"))),
    }
