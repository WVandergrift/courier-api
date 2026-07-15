#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <incoming-directory> <vMAJOR.MINOR.PATCH> <firmware|desktop>" >&2
  exit 64
fi

incoming=$1
tag=$2
kind=$3
publish_root=${COURIER_FIRMWARE_ROOT:-/var/www/courier-firmware}
root="$publish_root/ember-core"

[[ $incoming == "$publish_root"/.incoming-* ]] || {
  echo "incoming directory is outside the release staging area" >&2
  exit 65
}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "invalid release tag: $tag" >&2
  exit 65
}
[[ $kind == firmware || $kind == desktop ]] || {
  echo "invalid asset kind: $kind" >&2
  exit 65
}

source_dir="$incoming/$tag/$kind"
destination="$root/releases/$tag/$kind"
[[ -d $source_dir ]] || {
  echo "staged release directory is missing: $source_dir" >&2
  exit 66
}
if find "$source_dir" -type l -print -quit | grep -q .; then
  echo "release directories may not contain symbolic links" >&2
  exit 65
fi

mkdir -p "$(dirname "$destination")"
if [[ -e $destination ]]; then
  diff -qr "$source_dir" "$destination" >/dev/null || {
    echo "release assets are immutable and $destination already differs" >&2
    exit 73
  }
  rm -rf "$source_dir"
else
  mv "$source_dir" "$destination"
fi
find "$destination" -type d -exec chmod 755 {} +
find "$destination" -type f -exec chmod 644 {} +

if [[ $kind == firmware ]]; then
  manifest="$incoming/releases.json"
  [[ -f $manifest ]] || { echo "staged firmware manifest is missing" >&2; exit 66; }
  python3 -m json.tool "$manifest" >/dev/null
  install -m 644 "$manifest" "$root/releases.json.next"
  mv "$root/releases.json.next" "$root/releases.json"
else
  latest="$incoming/latest.json"
  [[ -f $latest ]] || { echo "staged desktop manifest is missing" >&2; exit 66; }
  python3 -m json.tool "$latest" >/dev/null
  mkdir -p "$root/desktop"
  install -m 644 "$latest" "$root/desktop/latest.json.next"
  mv "$root/desktop/latest.json.next" "$root/desktop/latest.json"
fi

rm -rf "$incoming"
