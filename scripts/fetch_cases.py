#!/usr/bin/env python3
"""Fetch the pinned, pure-Python demo-case libraries into ``cases/*/site``.

This deliberately is not a package installer: every required dependency is an
explicit wheel in the case manifest, and wheel metadata/native extensions are
not part of the runnable case tree.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import tempfile
import tomllib
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"
STAMP = ".fetch-stamp.json"


def _manifest(case_file: Path) -> list[dict[str, str]]:
    data = tomllib.loads(case_file.read_text(encoding="utf-8"))
    return [
        {key: str(wheel[key]) for key in ("name", "version", "url", "sha256")}
        for wheel in data["wheels"]
    ]


def _stamp(manifest: list[dict[str, str]]) -> str:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"


def _download(wheel: dict[str, str]) -> bytes:
    with urllib.request.urlopen(wheel["url"]) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != wheel["sha256"]:
        raise RuntimeError(
            f"sha256 mismatch for {wheel['name']} {wheel['version']}: "
            f"expected {wheel['sha256']}, got {actual}"
        )
    return data


def _unpack_package_dirs(wheel_data: bytes, destination: Path) -> None:
    """Copy only importable package trees; omit metadata and native modules."""
    with zipfile.ZipFile(io.BytesIO(wheel_data)) as archive:
        for member in archive.infolist():
            name = member.filename
            parts = Path(name).parts
            if (
                member.is_dir()
                or len(parts) < 2
                or Path(name).is_absolute()
                or ".." in parts
                or any(part.endswith((".dist-info", ".data")) for part in parts)
                or name.endswith((".so", ".pyd", ".pyc"))
            ):
                continue
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def fetch(case_dir: Path) -> str:
    manifest = _manifest(case_dir / "case.toml")
    expected_stamp = _stamp(manifest)
    site = case_dir / "site"
    stamp = site / STAMP
    if site.is_dir() and stamp.is_file() and stamp.read_text(encoding="utf-8") == expected_stamp:
        return "already fetched"

    # Verify every artifact before replacing an existing extracted tree.
    wheels = [_download(wheel) for wheel in manifest]
    with tempfile.TemporaryDirectory(prefix=f"{case_dir.name}-", dir=case_dir) as temp:
        staging = Path(temp) / "site"
        staging.mkdir()
        for wheel_data in wheels:
            _unpack_package_dirs(wheel_data, staging)
        (staging / STAMP).write_text(expected_stamp, encoding="utf-8")
        if site.exists():
            shutil.rmtree(site)
        shutil.move(str(staging), str(site))
    return "fetched"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", nargs="*", help="optional CVE IDs to fetch")
    args = parser.parse_args()
    requested = set(args.case)
    case_dirs = [path for path in sorted(CASES.iterdir()) if (path / "case.toml").is_file()]
    if requested:
        known = {path.name for path in case_dirs}
        unknown = requested - known
        if unknown:
            parser.error(f"unknown case(s): {', '.join(sorted(unknown))}")
        case_dirs = [path for path in case_dirs if path.name in requested]
    for case_dir in case_dirs:
        print(f"{case_dir.name}: {fetch(case_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
