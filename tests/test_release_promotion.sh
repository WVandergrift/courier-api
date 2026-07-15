#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
export COURIER_FIRMWARE_ROOT="$temporary/origin"
promote="$repository_root/deploy/promote-release-assets.sh"
tag=v1.2.3

stage_firmware() {
  local incoming=$1
  mkdir -p "$incoming/$tag/firmware"
  printf 'firmware-bytes' > "$incoming/$tag/firmware/ember-core-oelo-esp32.bin"
  printf '{"schema":"ember-firmware-releases-v1","releases":[]}' > "$incoming/releases.json"
}

first="$COURIER_FIRMWARE_ROOT/.incoming-first"
stage_firmware "$first"
"$promote" "$first" "$tag" firmware
test -f "$COURIER_FIRMWARE_ROOT/ember-core/releases/$tag/firmware/ember-core-oelo-esp32.bin"
python3 -m json.tool "$COURIER_FIRMWARE_ROOT/ember-core/releases.json" >/dev/null

identical="$COURIER_FIRMWARE_ROOT/.incoming-identical"
stage_firmware "$identical"
"$promote" "$identical" "$tag" firmware

changed="$COURIER_FIRMWARE_ROOT/.incoming-changed"
stage_firmware "$changed"
printf 'different-bytes' > "$changed/$tag/firmware/ember-core-oelo-esp32.bin"
if "$promote" "$changed" "$tag" firmware 2>/dev/null; then
  echo "changed release assets were incorrectly accepted" >&2
  exit 1
fi

printf 'Release promotion fixtures passed\n'
