# Courier API

> **Simple for consumers. Open for developers.**

Courier is the coordination service for Ember installations. It provides:

- controller identity bootstrap, passwordless installation enrollment, and
  approved-client controller-add grants;
- signed new-board sightings with installation-wide notification deduplication;
- APNs push delivery and an authenticated delivery dashboard;
- Apple Universal Link and Android App Link association files;
- the safe HTTPS landing route encoded on Ember Home Key NFC stickers;
- an optional outbound WebSocket relay for installations behind NAT.

Lighting control and Home Key ownership proof remain local. Courier stores
public installation identities and short-lived challenges, not the NFC Home
Key secret.

## Local development

Requires Python 3.12 or newer.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
pytest
uvicorn app.main:app --reload
```

Set a non-empty `COURIER_API_TOKEN` in `.env`. APNs settings are optional for
installation enrollment tests but required to send a real notification.

Useful local URLs:

- API health: `http://127.0.0.1:8000/health`
- OpenAPI UI: `http://127.0.0.1:8000/docs`
- Authenticated delivery dashboard: `http://127.0.0.1:8000/dashboard`

## API surfaces

| Surface | Paths | Purpose |
|---|---|---|
| Installation identity | `/v1/ember/*` | Register controllers and complete signed client enrollment |
| iOS push | `POST /v1/push/ios` | Send a structured APNs notification |
| Delivery events | `GET /v1/events`, `/dashboard` | Inspect redacted provider results |
| Companion relay | `/v1/relay/*` | Route authenticated off-LAN request/response frames |
| Home Key links | `/ember/t/{tagId}` | Open Ember without exposing the URI fragment secret |
| Platform association | `/.well-known/*` | Associate `emberhome.lighting` with the Ember apps |

Every protected administrative endpoint accepts
`Authorization: Bearer $COURIER_API_TOKEN`. The dashboard also accepts HTTP
Basic authentication with any username and the token as its password.

## Configuration

Copy `.env.example`; never commit the populated file.

| Variable | Required | Description |
|---|---|---|
| `COURIER_API_TOKEN` | Yes | Shared administrative and service credential |
| `COURIER_DB_PATH` | Production | SQLite database path; defaults to `/data/courier.db` |
| `APNS_TEAM_ID` | For push | Apple Developer team ID |
| `APNS_KEY_ID` | For push | APNs signing key ID |
| `APNS_PRIVATE_KEY_BASE64` | For push | Base64-encoded APNs `.p8` contents |
| `DEFAULT_APNS_TOPIC` | Optional | Default app bundle ID for push requests |
| `EMBER_ANDROID_CERT_SHA256` | Production links | Comma-separated Android release signing fingerprints |
| `COURIER_LOG_LEVEL` | Optional | Application log level; defaults to `INFO` |

## Verification

```sh
pytest
docker build -t courier-api:local .
docker run --rm --env-file .env -p 8000:8000 courier-api:local
```

Tests cover push authentication and validation, enrollment and controller-add
identity/signature/replay rules, database behavior, and relay
registration/routing policy.

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Ember installation enrollment](docs/ember-installations.md)
- [Temporary stock Oelo diagnostics](docs/oelo-diagnostics.md)
- [Public Ember update origin](docs/firmware-updates.md)
- [Production deployment](DEPLOYMENT.md)
- [DNS and TLS bootstrap](DNS.md)
- [Security policy](SECURITY.md)
- [Main Ember app and controller firmware](https://github.com/WVandergrift/ember-core)
- [Ember Commissioner](https://github.com/WVandergrift/ember-commissioner)

## Production

Production is served at [emberhome.lighting](https://emberhome.lighting).
`courier.systems` remains a compatibility origin for existing clients and Home
Keys. The Docker, systemd, nginx, persistence, redeployment, and TLS procedures
are documented in [DEPLOYMENT.md](DEPLOYMENT.md).
