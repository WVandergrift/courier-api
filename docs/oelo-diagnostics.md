# Temporary stock Oelo diagnostics

Courier exposes an ephemeral, administrator-created log buffer for controlled
stock Oelo bench testing. It is not ordinary product telemetry and it does not
persist log contents to SQLite.

## Trust model

- Creating, reading, and deleting a session requires `COURIER_API_TOKEN`.
- Session creation binds one normalized 12-hex-digit hardware ID.
- Courier returns a random 256-bit-class ingest token once. The token can write
  only to that session and is stored in memory as a SHA-256 digest.
- The hardware ID labels the stream; it is not authentication.
- Ingest tokens belong in an `Authorization: Bearer` header, never a URL.
- Sessions expire after 10 minutes by default and no later than one hour.
- A session retains at most 512 lines and disappears on service restart.
- HTTPS is mandatory outside loopback development.

Stock output can contain SSIDs, identifiers, network addresses, or other
installation-specific state. Only enable a session with the owner's knowledge,
and do not copy a tail into tickets or chat without reviewing and redacting it.

## Create a session

```http
POST /v1/diagnostics/oelo/sessions
Authorization: Bearer <courier-admin-token>
Content-Type: application/json

{"hardwareId":"AABBCCDDEEFF","ttlSeconds":600}
```

The response includes `sessionId`, `ingestToken`, `expiresAt`, `ingestPath`,
and `tailPath`.

## Ingest newline-delimited output

```http
POST /v1/diagnostics/oelo/sessions/<session-id>/logs
Authorization: Bearer <session-ingest-token>
Content-Type: text/plain; charset=utf-8

Starting Oelo Controller
Firmware: 1.78
```

Each request is limited to 16 KiB and 64 lines. Each stored line is limited to
512 UTF-8 bytes, and each session accepts at most 10 requests per second.

## Poll the tail

```http
GET /v1/diagnostics/oelo/sessions/<session-id>/tail?after=0&limit=200
Authorization: Bearer <courier-admin-token>
```

Use the returned `nextCursor` as the next `after` value. Polling rather than a
long-lived stream keeps the first diagnostic implementation compatible with
the existing reverse proxy and simple firmware/bench clients.

Delete early when a test completes:

```http
DELETE /v1/diagnostics/oelo/sessions/<session-id>
Authorization: Bearer <courier-admin-token>
```
