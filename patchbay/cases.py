"""Curated, local-only demo case catalog."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Wheel:
    name: str
    version: str
    url: str
    sha256: str


@dataclass(frozen=True, slots=True)
class Case:
    id: str
    package: str
    vulnerable_version: str
    fixed_version: str
    license: str
    cwe: str
    summary: str
    advisory_urls: tuple[str, ...]
    target: str
    wheels: tuple[Wheel, ...]
    attribution: str
    repro_timeout: float
    root: Path
    site: Path


def _cases_root() -> Path:
    override = os.environ.get("PATCHBAY_CASES_DIR")
    return Path(override).expanduser().resolve() if override else Path(__file__).resolve().parents[1] / "cases"


def _read_case(root: Path) -> Case:
    with (root / "case.toml").open("rb") as source:
        data = tomllib.load(source)
    return Case(
        id=data["id"],
        package=data["package"],
        vulnerable_version=data["vulnerable_version"],
        fixed_version=data["fixed_version"],
        license=data["license"],
        cwe=data["cwe"],
        summary=data["summary"],
        advisory_urls=tuple(data["advisory_urls"]),
        target=data["target"],
        wheels=tuple(Wheel(**wheel) for wheel in data["wheels"]),
        attribution=data["attribution"],
        repro_timeout=float(data["repro_timeout"]),
        root=root,
        site=root / "site",
    )


def list_cases() -> list[Case]:
    root = _cases_root()
    return [_read_case(path) for path in sorted(root.iterdir()) if (path / "case.toml").is_file()]


def load_case(case_id: str) -> Case:
    root = _cases_root() / case_id
    if not (root / "case.toml").is_file():
        raise KeyError(f"unknown curated case: {case_id}")
    return _read_case(root)
