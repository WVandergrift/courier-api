# Public Ember update origin

Courier hosts public release artifacts at `https://firmware.courier.systems`
while Ember source and build records remain private on GitHub.

## Paths

- `/ember-core/releases.json` — `ember-firmware-releases-v1` controller manifest
- `/ember-core/releases/vMAJOR.MINOR.PATCH/firmware/` — immutable controller images and checksums
- `/ember-core/releases/vMAJOR.MINOR.PATCH/desktop/` — immutable desktop bundles and updater signatures
- `/ember-core/desktop/latest.json` — current signed Tauri updater manifest

The manifests are intentionally unauthenticated and contain no installation or
customer data. Downloads are public because embedded controllers and shipped
apps cannot safely hold a GitHub repository token. Firmware still validates
TLS, the exact origin and path, declared size, SHA-256, ESP32 image structure,
and its provisional OTA boot before accepting an update.

The release publisher stages a complete directory and promotes it atomically.
An existing version may be re-published only when every byte is identical; a
different artifact requires a new semantic-version patch release.
