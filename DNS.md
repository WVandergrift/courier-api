# DNS for `emberhome.lighting`

The Ember API and public firmware origin run on the DigitalOcean droplet at
`157.245.126.211`. The browser flasher runs on OpenAI Sites and uses its custom
domain target instead of the droplet.

## Required records

| Type | Host | Value | TTL |
| --- | --- | --- | --- |
| A | `@` | `157.245.126.211` | 300 |
| A | `www` | `157.245.126.211` | 300 |
| A | `firmware` | `157.245.126.211` | 300 |
| CNAME | `flash` | `custom-domains.chatgpt.site.` | 300 |
| TXT | `_openai-site-verification.flash` | `openai-site-verification=wU4uR2hAfyzYp_gDgs2sozoKEVn2-Bnqsi1XqfZeTlU` | 300 |
| TXT | `_cf-custom-hostname.flash` | `9d18efe7-3778-4a38-b172-a7bf55e22cf3` | 300 |

Remove any `A` or `AAAA` record for `flash` before adding the CNAME. If the DNS
provider does not accept the trailing dot in the CNAME target, omit it.

The legacy `courier.systems`, `www.courier.systems`, and
`firmware.courier.systems` records must remain pointed at the same droplet for
installed clients, controllers, NFC stickers, and immutable release manifests.

## HTTPS on the droplet

After the apex, `www`, and `firmware` records resolve, expand the existing
certificate without changing its on-disk name:

```bash
ssh root@157.245.126.211
certbot --nginx --cert-name courier.systems \
  -d emberhome.lighting -d www.emberhome.lighting -d firmware.emberhome.lighting \
  -d courier.systems -d www.courier.systems -d firmware.courier.systems \
  --redirect --non-interactive --agree-tos -m will.vandergrift@outlook.com
systemctl reload nginx
```

OpenAI Sites provisions TLS for `flash.emberhome.lighting` after the CNAME and
both validation TXT records are visible.
