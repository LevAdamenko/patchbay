"""Tests for scripts/export_static_demo.py (static replay page for hosting)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from patchbay import pipeline
from patchbay.cases import list_cases
from patchbay.pipeline import PipelineRefused
from patchbay.web import _render_index_html
from scripts import export_static_demo


def _fake_run(case, *, settings, on_event):
    assert settings.live is False
    for stage in ["research", "brief", "repro", "patch", "mutate", "report"]:
        on_event({"stage": stage, "status": "start", "detail": stage, "evidence_hash": None})
        on_event({"stage": stage, "status": "ok", "detail": stage, "evidence_hash": None})
    return f"# Report {case.id}\n"


def test_export_writes_page_and_one_timed_run_per_case(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pipeline, "run", _fake_run)
    assert export_static_demo.main(["--out", str(tmp_path)]) == 0

    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "const STATIC_REPLAY = true;" in page
    assert 'fetch("data/"' in page
    assert "Run the real pipeline yourself" in page

    for case in list_cases():
        assert case.id in page
        run = json.loads((tmp_path / "data" / f"{case.id}.json").read_text(encoding="utf-8"))
        assert run["case_id"] == case.id
        events = run["events"]
        assert len(events) == 13
        times = [ev["t"] for ev in events]
        assert times == sorted(times)
        assert all(ev["event"] == "stage" for ev in events[:-1])
        assert events[-1] == {
            "t": events[-1]["t"],
            "event": "report",
            "data": {"case_id": case.id, "markdown": f"# Report {case.id}\n"},
        }


def test_refused_run_is_exported_and_fails_the_command(tmp_path: Path, monkeypatch):
    def refuse(case, *, settings, on_event):
        on_event({"stage": "repro", "status": "fail", "detail": "no", "evidence_hash": None})
        raise PipelineRefused("repro", "no")

    monkeypatch.setattr(pipeline, "run", refuse)
    assert export_static_demo.main(["--out", str(tmp_path)]) == 1
    run = json.loads((tmp_path / "data" / f"{list_cases()[0].id}.json").read_text(encoding="utf-8"))
    assert run["events"][-1]["event"] == "refused"
    assert run["events"][-1]["data"] == {"stage": "repro", "reason": "no"}


def test_server_page_stays_live_streaming():
    page = _render_index_html()
    assert "const STATIC_REPLAY = false;" in page
    assert "Run the real pipeline yourself" not in page
