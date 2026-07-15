# Security

Report suspected vulnerabilities privately to the repository owner. Do not
open a public issue containing credentials, NFC Home Keys, controller identity
material, APNs device tokens, or production infrastructure access details.

Never commit `.env` files, APNs `.p8` keys, API tokens, SQLite databases, or
production backups. The repository ignores these paths; verify staged content
before every push.

The public `/health`, Home Key landing, and platform association endpoints are
intentionally unauthenticated. Administrative and push endpoints require
`COURIER_API_TOKEN`. Installation enrollment additionally relies on
short-lived challenges and controller signatures as documented in
`docs/ember-installations.md`.
