# Deployment

## Current Production Host

- DigitalOcean droplet: `courier-api-01`
- Region: `nyc3`
- Size: `s-1vcpu-1gb` (`$6/month`)
- IPv4: `157.245.126.211`
- App directory: `/opt/courier`
- Systemd service: `courier.service`
- Public health check: `https://emberhome.lighting/health` (HTTP on the bare IP now
  301s/404s — nginx redirects recognized Ember hosts to HTTPS and returns 404 for the
  IP host; use the HTTPS URL)

The generated production API token is stored locally in `.env.production` and remotely in `/opt/courier/.env`.

## Redeploy

From a clean, pushed checkout, use the local deployment helper:

```bash
./deploy/deploy-local.sh
```

It runs the API and deployment tests, builds the container locally, deploys the
tracked source, restarts Courier, and verifies the public health endpoint.
Local environments, databases, caches, and credentials are excluded. Override
`COURIER_HOST`, `COURIER_USER`, or `COURIER_HEALTH_URL` when targeting a
different host.

The health response includes the full deployed Git revision. Ember's local
release runner uses it to skip Courier when the checkout already matches
production.

The equivalent manual process is:

```bash
export COURIER_HOST=157.245.126.211
rsync -az --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'data' \
  --exclude '.env*' \
  --exclude '.pytest_cache' \
  --exclude '__pycache__' \
  ./ root@$COURIER_HOST:/opt/courier/

ssh root@$COURIER_HOST '
  set -euo pipefail
  docker build -t courier-api:latest /opt/courier
  cp /opt/courier/deploy/courier.service /etc/systemd/system/courier.service
  cp /opt/courier/deploy/nginx.conf /etc/nginx/sites-available/courier
  ln -sf /etc/nginx/sites-available/courier /etc/nginx/sites-enabled/courier
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl reload nginx
  systemctl daemon-reload
  systemctl restart courier.service
'
```

The deploy does not copy `.env.production`; production secrets remain in
`/opt/courier/.env` on the host.

## Operations

```bash
ssh root@$COURIER_HOST 'systemctl status courier.service'
ssh root@$COURIER_HOST 'docker logs --tail 200 courier-api'
ssh root@$COURIER_HOST 'journalctl -u courier.service -n 200 --no-pager'
ssh root@$COURIER_HOST 'sqlite3 /opt/courier/data/courier.db "select id, created_at, status, environment, apns_topic from push_events order by id desc limit 20;"'
```

Logs are JSON. Useful event names:

- `client_request_received`
- `push_request_accepted`
- `apns_request_sent`
- `apns_response_received`
- `push_response_prepared`
- `client_response_sent`

## HTTPS

`deploy/nginx.conf` is the **full** config including the `:443` server block, so
the redeploy above preserves HTTPS (it used to revert to HTTP-only, which broke
the daemon's `https://emberhome.lighting/...` pushes with `fetch failed`). The TLS
cert lives at `/etc/letsencrypt/live/courier.systems/`; renewals only swap the
cert files at those paths and don't touch the nginx block, so they don't
conflict with a redeploy.

**Bootstrap only** — on a fresh host the cert doesn't exist yet, so `nginx -t`
would fail on the `ssl_certificate` lines. Issue it once after the DNS records
in `DNS.md` propagate; `certonly` leaves the repository-owned nginx blocks intact:

```bash
ssh root@$COURIER_HOST
certbot certonly --nginx --cert-name courier.systems --expand \
  -d emberhome.lighting -d www.emberhome.lighting -d firmware.emberhome.lighting -d flash.emberhome.lighting \
  -d courier.systems -d www.courier.systems -d firmware.courier.systems -d flash.courier.systems \
  --non-interactive --agree-tos -m will.vandergrift@outlook.com
systemctl reload nginx
```

The nginx configuration owns the `:443` blocks. Re-run the `certbot certonly`
command only when the certificate's hostname set changes; routine renewals reuse
the same on-disk certificate path.

The firmware origin serves a validated chain derived from Certbot's full chain
that stops before the cross-signed ISRG Root X2 certificate. ESP32 controllers
already trust the compact self-signed X2 root, and omitting the redundant
cross-sign lets their constrained mbedTLS verifier terminate at that anchor.
`deploy-local.sh` installs the derived chain and a Certbot deploy hook so it is
rebuilt and nginx is reloaded after every successful renewal.

Controllers also receive a compact view of the five newest firmware releases
at the normal manifest URL, selected by their HTTP User-Agent. The full public
manifest remains unchanged for apps, release tooling, and browsers. Deployment
and firmware promotion both regenerate the compact view atomically.

## Browser flasher

`flash.emberhome.lighting` is served directly by nginx from
`/var/www/ember-flasher`. Its source and deployment helper live in the
`flasher/` directory of the private `ember-core` repository. The flasher deploy
atomically replaces that directory and verifies the page, board catalog, and an
immutable firmware download. Courier deployments preserve the files because
they live outside `/opt/courier`.

## Public release assets

`firmware.emberhome.lighting` serves immutable, versioned Ember artifacts from
`/var/www/courier-firmware`. It is deliberately separate from the Courier API
and exposes only files explicitly promoted by the release workflow. Manifests
are no-cache; versioned firmware and desktop assets are cached as immutable.
The public allow-list also exposes the versioned hardware-profile catalog,
schema, and sanitized WebP reference photos. Public release responses include
wildcard CORS because they contain no credentials or private data and must be
readable by the browser-based Ember board flasher.

The legacy `courier.systems` API and firmware names remain on the certificate
and nginx server blocks for installed apps, controllers, NFC stickers, and
published manifests that already contain those origins.

Create the least-privileged publisher account once and install the public half
of the dedicated GitHub Actions deploy key:

```bash
useradd --create-home --shell /bin/bash firmware-publisher
install -d -o firmware-publisher -g firmware-publisher -m 755 /var/www/courier-firmware
install -d -o firmware-publisher -g firmware-publisher -m 700 /home/firmware-publisher/.ssh
install -o firmware-publisher -g firmware-publisher -m 600 /dev/null /home/firmware-publisher/.ssh/authorized_keys
# Append the dedicated public key to authorized_keys.
```

The private half is stored only as the private `ember-core` repository secret
`COURIER_FIRMWARE_SSH_KEY`. The account has no sudo access. GitHub Actions
uploads into a run-specific `.incoming-*` directory, then invokes
`/opt/courier/deploy/promote-release-assets.sh` to verify the tag, reject
symlinks and changed releases, and atomically replace only the current manifest.
