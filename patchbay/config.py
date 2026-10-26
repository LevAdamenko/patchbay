"""Configuration loaded from environment variables and an optional secrets file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_SECRETS_FILE = Path("~/.config/hackathon/secrets.env").expanduser()


def _read_secrets(path: Path) -> dict[str, str]:
    """Read simple KEY=VALUE lines, ignoring comments and malformed lines."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip().strip('"').strip("'")
    return values


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _mask(value: str | None) -> str:
    return "<set>" if value else "<unset>"


@dataclass(repr=False, slots=True)
class Settings:
    nebius_api_key: str | None
    tavily_api_key: str | None
    nemotron_model: str
    nemotron_fallback_model: str
    nebius_base_url: str
    live: bool
    fixtures_dir: Path
    nemotron_max_tokens: int

    def __init__(self) -> None:
        secrets_path = Path(
            os.environ.get("PATCHBAY_SECRETS_FILE", str(DEFAULT_SECRETS_FILE))
        ).expanduser()
        secrets = _read_secrets(secrets_path)

        def get(name: str, default: str | None = None) -> str | None:
            return os.environ.get(name, secrets.get(name, default))

        self.nebius_api_key = get("NEBIUS_API_KEY")
        self.tavily_api_key = get("TAVILY_API_KEY")
        self.nemotron_model = get(
            "NEMOTRON_MODEL", "nvidia/nemotron-3-super-120b-a12b"
        ) or "nvidia/nemotron-3-super-120b-a12b"
        self.nemotron_fallback_model = get(
            "NEMOTRON_FALLBACK_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b"
        ) or "nvidia/Nemotron-3-Ultra-550b-a55b"
        self.nebius_base_url = get(
            "NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1"
        ) or "https://api.tokenfactory.nebius.com/v1"
        self.live = _as_bool(get("LIVE"), default=False)
        self.fixtures_dir = Path(get("FIXTURES_DIR", "fixtures") or "fixtures")
        max_tokens_val = get("NEMOTRON_MAX_TOKENS", "32768") or "32768"
        self.nemotron_max_tokens = int(max_tokens_val)

    def __repr__(self) -> str:
        return (
            "Settings("
            f"nebius_api_key={_mask(self.nebius_api_key)}, "
            f"tavily_api_key={_mask(self.tavily_api_key)}, "
            f"nemotron_model={self.nemotron_model!r}, "
            f"nemotron_fallback_model={self.nemotron_fallback_model!r}, "
            f"nebius_base_url={self.nebius_base_url!r}, live={self.live!r}, "
            f"fixtures_dir={str(self.fixtures_dir)!r}, "
            f"nemotron_max_tokens={self.nemotron_max_tokens!r})"
        )

