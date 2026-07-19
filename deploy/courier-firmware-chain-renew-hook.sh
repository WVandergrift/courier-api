#!/usr/bin/env bash

set -euo pipefail

/opt/courier/deploy/install-firmware-tls-chain.sh
nginx -t
systemctl reload nginx
