#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

host=${COURIER_HOST:-157.245.126.211}
user=${COURIER_USER:-root}
health_url=${COURIER_HEALTH_URL:-https://emberhome.lighting/health}
target="$user@$host"

if [[ -n $(git status --short) ]]; then
  echo "Refusing to deploy a dirty checkout. Commit the verified changes first." >&2
  exit 1
fi

upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
if [[ -z "$upstream" ]]; then
  echo "Refusing to deploy without a configured upstream branch." >&2
  exit 1
fi
if [[ $(git rev-parse HEAD) != $(git rev-parse "$upstream") ]]; then
  echo "Refusing to deploy a revision that has not been pushed to $upstream." >&2
  exit 1
fi

python_bin=python3
if [[ -x .venv/bin/python ]]; then
  python_bin=.venv/bin/python
fi

"$python_bin" -m pytest
docker build -t courier-api:local .
python3 -m py_compile deploy/build-controller-release-manifest.py
bash -n deploy/install-firmware-tls-chain.sh
bash -n deploy/courier-firmware-chain-renew-hook.sh
bash -n deploy/promote-release-assets.sh
bash tests/test_release_promotion.sh

rsync -az --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'data' \
  --exclude '.env*' \
  --exclude '.pytest_cache' \
  --exclude '__pycache__' \
  ./ "$target:/opt/courier/"

ssh "$target" '
  set -euo pipefail
  docker build -t courier-api:latest /opt/courier
  cp /opt/courier/deploy/courier.service /etc/systemd/system/courier.service
  /opt/courier/deploy/install-firmware-tls-chain.sh
  /opt/courier/deploy/build-controller-release-manifest.py \
    /var/www/courier-firmware/ember-core/releases.json \
    /var/www/courier-firmware/ember-core/controller-releases.json
  ln -sf /opt/courier/deploy/courier-firmware-chain-renew-hook.sh \
    /etc/letsencrypt/renewal-hooks/deploy/courier-firmware-chain
  cp /opt/courier/deploy/nginx.conf /etc/nginx/sites-available/courier
  ln -sf /etc/nginx/sites-available/courier /etc/nginx/sites-enabled/courier
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl reload nginx
  systemctl daemon-reload
  systemctl restart courier.service
  systemctl is-active --quiet courier.service
'

healthy=false
for _ in {1..12}; do
  if curl --fail --silent "$health_url" >/dev/null 2>&1; then
    healthy=true
    break
  fi
  sleep 2
done
if [[ "$healthy" != true ]]; then
  echo "Courier restarted, but its public health check did not recover." >&2
  curl --fail --silent --show-error "$health_url" >/dev/null
  exit 1
fi

printf 'Courier deployed from %s and healthy at %s\n' "$(git rev-parse --short HEAD)" "$health_url"
