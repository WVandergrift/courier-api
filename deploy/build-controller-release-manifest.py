#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


MAX_CONTROLLER_RELEASES = 5
RELEASE_FIELDS = ("version", "name", "publishedAt", "prerelease", "assets")


def compact_manifest(source: Path) -> dict[str, object]:
    document = json.loads(source.read_text(encoding="utf-8"))
    releases = document.get("releases")
    if document.get("schema") != "ember-firmware-releases-v1" or not isinstance(
        releases, list
    ):
        raise ValueError("unsupported firmware release manifest")

    compact_releases: list[dict[str, object]] = []
    for release in releases[:MAX_CONTROLLER_RELEASES]:
        if not isinstance(release, dict) or not isinstance(release.get("assets"), dict):
            raise ValueError("firmware release entry is missing its assets")
        compact_releases.append(
            {field: release[field] for field in RELEASE_FIELDS if field in release}
        )

    return {
        "schema": "ember-firmware-releases-v1",
        "releases": compact_releases,
    }


def write_atomic(output: Path, document: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.name}.", text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary:
            json.dump(document, temporary, separators=(",", ":"))
            temporary.write("\n")
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, output)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: build-controller-release-manifest.py <source> <output>",
            file=sys.stderr,
        )
        return 64
    source, output = map(Path, sys.argv[1:])
    write_atomic(output, compact_manifest(source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
