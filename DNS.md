# DNS for `emberhome.lighting`

The Ember API, public firmware origin, and browser flasher run on the
DigitalOcean droplet at `157.245.126.211`.

## Required records

| Type | Host | Value | TTL |
| --- | --- | --- | --- |
| A | `@` | `157.245.126.211` | 300 |
| A | `www` | `157.245.126.211` | 300 |
| A | `firmware` | `157.245.126.211` | 300 |
| A | `flash` | `157.245.126.211` | 300 |

The old managed-hosting validation TXT records for `flash` are no longer used
and may be removed.

The legacy `courier.systems`, `www.courier.systems`, and
`firmware.courier.systems` records must remain pointed at the same droplet for
installed clients, controllers, NFC stickers, and immutable release manifests.

## HTTPS on the droplet

After the apex, `www`, `firmware`, and `flash` records resolve, expand the existing
certificate without changing its on-disk name:

```bash
ssh root@157.245.126.211
certbot certonly --nginx --cert-name courier.systems --expand \
  -d emberhome.lighting -d www.emberhome.lighting -d firmware.emberhome.lighting -d flash.emberhome.lighting \
  -d courier.systems -d www.courier.systems -d firmware.courier.systems -d flash.courier.systems \
  --non-interactive --agree-tos -m will.vandergrift@outlook.com
systemctl reload nginx
```
