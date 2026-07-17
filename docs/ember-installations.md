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
| `POST` | `/v1/ember/controller-add-grants` | Existing installation member identity | Create an exact, short-lived controller capability |
| `POST` | `/v1/ember/controller-add-grants/{id}/authorize` | Existing client P-256 signature | Approve the controller capability |
| `POST` | `/v1/ember/enrollment-challenges` | Public, rate-limited by deployment edge | Begin a short-lived ownership challenge |
| `POST` | `/v1/ember/enrollment-challenges/{id}/complete` | Controller signature | Consume the challenge and enroll the client |
| `POST` | `/v1/ember/client-join-requests` | Nearby controller ID and candidate key | Create an expiring request for existing clients to review |
| `POST` | `/v1/ember/client-join-requests/pending` | Existing client signature | List undecided requests for an installation |
| `POST` | `/v1/ember/client-join-requests/{id}/decision` | Existing client signature | Approve or deny one exact candidate key |
| `POST` | `/v1/ember/client-invitations` | Existing member locator | Prepare a 60-second one-time Share Home invitation |
| `POST` | `/v1/ember/client-invitations/{id}/authorize` | Existing client signature | Authorize the exact invitation secret hash and expiry |
| `POST` | `/v1/ember/client-invitations/{id}/redeem` | One-time invitation secret | Enroll the scanning client and consume the invitation |

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

## Adding a controller to an existing installation

Ordinary enrollment of an unclaimed controller creates a new installation. To
add it to an existing Home, the app first creates and signs a controller-add
grant. The client signs these exact UTF-8 bytes with the same hardware-backed
P-256 key recorded on its active administrator member:

```text
ember-controller-add-grant/v1
<grantId>
<installationId>
<authorizerMemberId>
<controllerId>
<controllerKeyThumbprint>
<tagId>
<hardwareModel>
<clientKeyThumbprint>
<serverNonce>
<expiresAt>
```

The resulting grant ID is included when beginning controller enrollment.
Courier rechecks every bound field, the member capability and revocation state,
and the controller's unclaimed state. It consumes the grant and creates the
controller member inside the same immediate transaction. A replay, expiry,
identity substitution, cross-installation use, or claimed controller fails.

NFC stickers are associated with controllers during setup and enrollment, not
by the sticker's factory NFC UID. Each controller may have its own tag. For
Test-button enrollment, firmware uses `controller_<controllerId>` as a
non-secret synthetic tag ID so the signed protocol still binds a stable
controller-specific identity.

## Data handling

Courier stores the public tag ID and public identities. It never receives the
Home Key secret. Revocation and additional-device approval should operate on
installation members, not shared passwords.
