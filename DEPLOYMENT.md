# Deployment

## Current Production Host

- DigitalOcean droplet: `courier-api-01`
- Region: `nyc3`
- Size: `s-1vcpu-1gb` (`$6/month`)
- IPv4: `157.245.126.211`
- App directory: `/opt/courier`
- Systemd service: `courier.service`
- Public health check: `https://courier.systems/health` (HTTP on the bare IP now
  301s/404s — certbot redirects `courier.systems`→HTTPS and returns 404 for the
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
the daemon's `https://courier.systems/...` pushes with `fetch failed`). The TLS
cert lives at `/etc/letsencrypt/live/courier.systems/`; renewals only swap the
cert files at those paths and don't touch the nginx block, so they don't
conflict with a redeploy.

**Bootstrap only** — on a fresh host the cert doesn't exist yet, so `nginx -t`
would fail on the `ssl_certificate` lines. Issue it once (after the DNS records
in `DNS.md` propagate), which also (re)writes the nginx block:

```bash
ssh root@$COURIER_HOST
certbot --nginx -d courier.systems -d www.courier.systems --redirect --non-interactive --agree-tos -m will.vandergrift@outlook.com
systemctl reload nginx
```

If HTTPS ever regresses to HTTP-only after a deploy, re-run that certbot command
to restore the `:443` block (it reuses the existing cert, no re-issue).
