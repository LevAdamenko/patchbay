"""The offline demo must say honestly which cases replay synthetic fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from patchbay.demo import replay_banner, synthetic_cases


def _write(case_dir: Path, name: str, synthetic: bool) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc = {"request": {}, "response": {}}
    if synthetic:
        doc["synthetic"] = True
    (case_dir / name).write_text(json.dumps(doc), encoding="utf-8")


def test_banner_all_live(tmp_path):
    _write(tmp_path / "A", "nemotron-1.json", False)
    _write(tmp_path / "B", "tavily-1.json", False)
    assert synthetic_cases(tmp_path, ["A", "B"]) == []
    assert replay_banner(tmp_path, ["A", "B"]) == (
        "offline replay of recorded live Nemotron and Tavily responses"
    )


def test_banner_names_the_synthetic_case_when_mixed(tmp_path):
    _write(tmp_path / "A", "nemotron-1.json", False)
    _write(tmp_path / "B", "nemotron-1.json", False)
    _write(tmp_path / "B", "tavily-1.json", True)
    banner = replay_banner(tmp_path, ["A", "B"])
    assert "live" in banner
    assert banner.endswith("synthetic fixtures for B")


def test_banner_all_synthetic_and_missing(tmp_path):
    _write(tmp_path / "A", "nemotron-1.json", True)
    assert synthetic_cases(tmp_path, ["A", "missing"]) == ["A", "missing"]
    assert replay_banner(tmp_path, ["A", "missing"]) == "offline replay of synthetic fixtures"
