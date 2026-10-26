"""Stable, scrubbed JSON request/response fixtures for offline runs."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


class FixtureMissing(FileNotFoundError):
    """Raised when an offline request has no recorded response."""


# Sandbox logs fed back to the model carry run-to-run noise: pytest's
# "1 passed in 0.02s", the sandbox's temporary directory and object addresses
# in tracebacks (<Mock at 0x7f...>). Hashing them
# would make a recorded retry unreplayable whenever a test ran 10 ms slower.
_VOLATILE = (
    (re.compile(r" in \d+(?:\.\d+)?s(?: \(\d+:\d\d:\d\d\))?"), " in <t>s"),
    (re.compile(r"patchbay-sandbox-[a-z0-9_]{8}"), "patchbay-sandbox-<dir>"),
    (re.compile(r"\b0x[0-9a-f]{6,}\b"), "0x<addr>"),
)


def _stable(text: str) -> str:
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def key(kind: str, payload: Any) -> str:
    canonical = json.dumps(
        {"kind": kind, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(_stable(canonical).encode("utf-8")).hexdigest()[:16]


def _path(directory: Path, kind: str, payload: Any) -> Path:
    return directory / f"{kind}-{key(kind, payload)}.json"


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for name, item in value.items():
            normalized = name.lower().replace("-", "_")
            if normalized == "authorization" or "api_key" in normalized or normalized.endswith("token"):
                continue
            clean[name] = _scrub(item)
        return clean
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub(item) for item in value]
    return value


def load(directory: Path, kind: str, payload: Any) -> Any:
    path = _path(Path(directory), kind, payload)
    if not path.is_file():
        raise FixtureMissing(f"Fixture missing: expected {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    return document["response"]


def save(directory: Path, kind: str, payload: Any, response: Any) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = _path(directory, kind, payload)
    document = {"request": _scrub(payload), "response": _scrub(response)}
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
