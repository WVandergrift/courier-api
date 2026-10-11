"""Guards deploy/nginx.conf: a redeploy copies it verbatim, so the API server
block must keep TLS and WebSocket upgrades for both relay sockets."""

from __future__ import annotations

import re
from pathlib import Path

NGINX_CONF = Path(__file__).resolve().parent.parent / "deploy" / "nginx.conf"


def _blocks(text: str, opener: str) -> list[str]:
    """Bodies of every `<opener> ... {}` block, matched by brace depth."""
    bodies = []
    for match in re.finditer(opener + r"\s*\{", text):
        depth, start = 1, match.end()
        for index in range(start, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(text[start:index])
                    break
    return bodies


def _api_server() -> str:
    text = re.sub(r"#.*", "", NGINX_CONF.read_text())
    servers = [b for b in _blocks(text, r"\bserver") if re.search(r"server_name[^;]*\bemberhome\.lighting\b", b) and "proxy_pass" in b]
    assert len(servers) == 1
    return servers[0]


def _location_for(server: str, path: str) -> str:
    """The prefix location nginx picks for `path` (longest prefix; this block uses no regex locations)."""
    assert not re.search(r"location\s+~", server)
    candidates = []
    for match in re.finditer(r"location\s+(=\s*)?(\S+)\s*\{", server):
        exact, prefix = match.group(1), match.group(2)
        if (exact and path == prefix) or (not exact and path.startswith(prefix)):
            candidates.append((bool(exact), len(prefix), match.start()))
    _exact, _length, start = max(candidates)
    return _blocks(server[start:], r"location\s+(?:=\s*)?\S+")[0]


def test_api_server_keeps_tls_on_443():
    server = _api_server()
    assert re.search(r"listen\s+443\s+ssl", server)
    assert re.search(r"ssl_certificate\s+/etc/letsencrypt/live/courier\.systems/fullchain\.pem;", server)
    assert re.search(r"ssl_certificate_key\s+/etc/letsencrypt/live/courier\.systems/privkey\.pem;", server)


def test_both_relay_websockets_are_proxied_with_upgrade_headers():
    server = _api_server()
    for path in ("/v1/relay/agent", "/v1/relay/AAAAkeyid/stream"):
        location = _location_for(server, path)
        assert "proxy_pass http://127.0.0.1:8000;" in location, path
        assert "proxy_http_version 1.1;" in location, path
        assert "proxy_set_header Upgrade $http_upgrade;" in location, path
        assert "proxy_set_header Connection $connection_upgrade;" in location, path
        read_timeout = re.search(r"proxy_read_timeout\s+(\d+)s;", location)
        assert read_timeout and int(read_timeout.group(1)) > 5 * 60, path
