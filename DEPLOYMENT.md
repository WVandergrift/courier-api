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

From the repository root, set the production host and deploy the tracked
source. Local environments, databases, caches, and credentials are excluded:

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

Run `pytest` and `docker build -t courier-api:local .` before redeploying.
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
would fail on the `ssl_certificate` lines. Issue it once (after the DNS records
in `DNS.md` propagate), which also (re)writes the nginx block:

```bash
ssh root@$COURIER_HOST
certbot --nginx --cert-name courier.systems \
  -d emberhome.lighting -d www.emberhome.lighting -d firmware.emberhome.lighting \
  -d courier.systems -d www.courier.systems -d firmware.courier.systems \
  --redirect --non-interactive --agree-tos -m will.vandergrift@outlook.com
systemctl reload nginx
```

If HTTPS ever regresses to HTTP-only after a deploy, re-run that certbot command
to restore the `:443` block (it reuses the existing cert, no re-issue).

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
