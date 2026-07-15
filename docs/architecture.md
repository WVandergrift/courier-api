# Architecture

Courier is the small public coordination plane for Ember. Lighting control
remains local; Courier supplies installation identity, short-lived ownership
challenges, push delivery, and an optional off-LAN relay.

```text
Ember app ---- enrollment challenge ----> Courier <---- controller identity
    |                                        |
    | local BLE + Home Key proof             +---- SQLite durable state
    |                                        +---- APNs
    +---------- local controller API         +---- optional relay WebSocket
```

## Services

### Installation identity

`app/ember_identity.py` registers controller public identities and completes
short-lived, signed installation-enrollment challenges. Courier stores public
keys, membership, capabilities, and audit events. The Home Key `tagKey` secret
is not sent to or stored by Courier.

### APNs delivery

`app/apns.py` signs requests to Apple Push Notification service with the
configured `.p8` key. The protected push endpoint records redacted delivery
events for operational diagnosis.

### Companion relay

`app/relay.py` maintains authenticated outbound WebSocket connections from
controllers or companion daemons behind NAT. It routes request/response frames
by public key identifier and enforces a narrow path allowlist. End-to-end
application authentication remains the responsibility of the peers; Courier
is a transport and must not be treated as an authorization authority for the
forwarded operation.

### Persistence

SQLite stores push delivery events, controller bootstraps, installations,
members, enrollment challenges, and audit events. The production database is
mounted at `/data/courier.db` inside the container.

## Trust boundaries

- `COURIER_API_TOKEN` protects administrative endpoints, controller bootstrap,
  the dashboard, and relay-agent registration.
- Controller enrollment completion requires a valid P-256 signature over the
  server challenge.
- Challenges expire after two minutes and are single-use.
- Device tokens are logged only as a hash, suffix, and length.
- Home Key secrets live in the URI fragment and are never included in the HTTP
  request to `emberhome.lighting` (or the supported legacy `courier.systems`
  origin).

## Runtime

Production runs one Uvicorn worker in a non-root Docker container, supervised
by systemd and exposed through nginx/TLS. SQLite and the in-memory relay hub
make the current deployment a single-instance service.
