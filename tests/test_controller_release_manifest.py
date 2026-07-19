import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "deploy" / "build-controller-release-manifest.py"
SPEC = spec_from_file_location("controller_manifest", SCRIPT)
assert SPEC and SPEC.loader
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_compacts_manifest_to_five_controller_releases(tmp_path: Path) -> None:
    source = tmp_path / "releases.json"
    source.write_text(
        json.dumps(
            {
                "schema": "ember-firmware-releases-v1",
                "releases": [
                    {
                        "version": f"v1.0.{index}",
                        "name": f"Release {index}",
                        "publishedAt": "2026-07-18T00:00:00Z",
                        "prerelease": False,
                        "notes": "not needed by controllers",
                        "assets": {"oelo_esp32": {"url": "https://example.test/fw.bin"}},
                    }
                    for index in range(7, 0, -1)
                ],
            }
        ),
        encoding="utf-8",
    )

    compact = MODULE.compact_manifest(source)

    assert [release["version"] for release in compact["releases"]] == [
        "v1.0.7",
        "v1.0.6",
        "v1.0.5",
        "v1.0.4",
        "v1.0.3",
    ]
    assert all("notes" not in release for release in compact["releases"])
    assert compact["releases"][0]["assets"]["oelo_esp32"]["url"].endswith(
        "fw.bin"
    )


def test_rejects_wrong_manifest_schema(tmp_path: Path) -> None:
    source = tmp_path / "releases.json"
    source.write_text('{"schema":"wrong","releases":[]}', encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported"):
        MODULE.compact_manifest(source)
