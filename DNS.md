# DNS for `courier.systems`

The API is deployed on a DigitalOcean droplet. Configure DNS wherever the authoritative DNS for `courier.systems` lives.

## Required records

Use the deployed droplet IPv4 address `157.245.126.211`.

| Type | Host | Value | TTL |
| --- | --- | --- | --- |
| A | `@` | `157.245.126.211` | 300 |
| A | `www` | `157.245.126.211` | 300 |
| A | `firmware` | `157.245.126.211` | 300 |

If Squarespace does not allow `@`, use the blank/root host field for the apex record.

## After DNS is pointed

SSH to the droplet and enable HTTPS:

```bash
ssh root@157.245.126.211
certbot --nginx --cert-name courier.systems -d courier.systems -d www.courier.systems -d firmware.courier.systems --redirect --non-interactive --agree-tos -m will.vandergrift@outlook.com
systemctl reload nginx
```

Until DNS is updated and the certificate is issued, the API is available over plain HTTP by IP address.
