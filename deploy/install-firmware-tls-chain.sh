#!/usr/bin/env bash

set -euo pipefail

source_fullchain=${SOURCE_FULLCHAIN:-/etc/letsencrypt/live/courier.systems/fullchain.pem}
output_fullchain=${OUTPUT_FULLCHAIN:-/etc/letsencrypt/firmware-fullchain.pem}
trust_anchor=${TRUST_ANCHOR:-/opt/courier/deploy/firmware-isrg-root-x2.pem}

for required in "$source_fullchain" "$trust_anchor"; do
  [[ -s $required ]] || {
    echo "Required TLS certificate file is missing or empty: $required" >&2
    exit 66
  }
done

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

awk -v output="$work_dir/cert-" '
  /-----BEGIN CERTIFICATE-----/ {
    certificate += 1
    path = output certificate ".pem"
  }
  path != "" { print > path }
  /-----END CERTIFICATE-----/ {
    close(path)
    path = ""
  }
' "$source_fullchain"

certificate_count=$(find "$work_dir" -name 'cert-*.pem' -type f | wc -l | tr -d ' ')
(( certificate_count >= 2 )) || {
  echo "Expected a leaf and at least one intermediate in $source_fullchain" >&2
  exit 65
}

anchor_subject=$(openssl x509 -in "$trust_anchor" -noout -subject -nameopt RFC2253)
anchor_subject=${anchor_subject#subject=}

: > "$work_dir/firmware-fullchain.pem"
included=0
for ((index = 1; index <= certificate_count; index += 1)); do
  certificate="$work_dir/cert-$index.pem"
  certificate_subject=$(openssl x509 -in "$certificate" -noout -subject -nameopt RFC2253)
  certificate_subject=${certificate_subject#subject=}

  # A TLS server must not send the trust anchor. In particular, Certbot's
  # current Let's Encrypt chain includes a cross-signed ISRG Root X2 after
  # Root YE. Older mbedTLS clients follow that certificate toward X1 instead
  # of terminating at their locally trusted, self-signed X2 certificate.
  if [[ $certificate_subject == "$anchor_subject" ]]; then
    break
  fi

  cat "$certificate" >> "$work_dir/firmware-fullchain.pem"
  included=$index
done

(( included >= 2 )) || {
  echo "Firmware TLS chain did not contain a usable intermediate" >&2
  exit 65
}

: > "$work_dir/intermediates.pem"
for ((index = 2; index <= included; index += 1)); do
  cat "$work_dir/cert-$index.pem" >> "$work_dir/intermediates.pem"
done

openssl verify \
  -CAfile "$trust_anchor" \
  -untrusted "$work_dir/intermediates.pem" \
  "$work_dir/cert-1.pem" >/dev/null

output_dir=$(dirname "$output_fullchain")
mkdir -p "$output_dir"
output_temp=$(mktemp "$output_dir/.firmware-fullchain.XXXXXX")
install -m 0644 "$work_dir/firmware-fullchain.pem" "$output_temp"
mv -f "$output_temp" "$output_fullchain"

printf 'Installed firmware TLS chain with %s certificates at %s\n' \
  "$included" "$output_fullchain"
