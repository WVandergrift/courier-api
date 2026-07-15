# Ember installation enrollment

Courier coordinates installation creation without requiring an end-user
login. Ownership is proven locally, then represented by asymmetric member keys.

## Bootstrap and enrollment

1. A controller has a stable controller ID and P-256 identity key.
2. A Commissioner-written NFC Home Key supplies a public `tagId` and local
   secret `tagKey`.
3. The controller bootstrap endpoint binds `controllerId`, `tagId`, public key,
   and hardware model. Factory bootstraps require Courier API authentication.
4. A new Ember client creates its own P-256 key and requests a two-minute
   enrollment challenge.
5. Local proof—Home Key over BLE or the controller Test button—authorizes the
   controller to sign the canonical challenge message.
6. Courier verifies the signature, creates the installation if necessary, and
   records controller and client memberships.

## Endpoints

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `POST` | `/v1/ember/controller-bootstraps` | Courier API token | Register a factory controller/tag association |
| `POST` | `/v1/ember/enrollment-challenges` | Public, rate-limited by deployment edge | Begin a short-lived ownership challenge |
| `POST` | `/v1/ember/enrollment-challenges/{id}/complete` | Controller signature | Consume the challenge and enroll the client |

The generated OpenAPI schema at `/docs` is the source of truth for request and
response fields.

## Canonical signature message

The controller signs UTF-8 bytes in this exact newline-delimited form:

```text
ember-courier-enrollment/v1
<proofMethod>
<challengeId>
<controllerId>
<tagId>
<clientKeyThumbprint>
<serverNonce>
```

Signatures are raw P-256 ECDSA `r || s`, 32 bytes each, encoded as unpadded
base64url. Public keys are uncompressed 65-byte P-256 points encoded the same
way.

## Data handling

Courier stores the public tag ID and public identities. It never receives the
Home Key secret. Revocation and additional-device approval should operate on
installation members, not shared passwords.
