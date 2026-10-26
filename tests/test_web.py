"""Tests for the PatchBay FastAPI web demo."""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from patchbay import pipeline
from patchbay.cases import Case, list_cases
from patchbay.pipeline import PipelineRefused
from patchbay.web import RUN_LOCK, app


def _require_site(case: Case) -> None:
    if not (case.site / case.target).is_file():
        pytest.skip(f"{case.id} site/ is not fetched; run: python scripts/fetch_cases.py")


def test_healthz():
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_get_root_returns_html_with_cases_and_eventsource():
    """a. GET / returns 200 HTML containing all 3 case ids and 'EventSource'."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    cases = list_cases()
    assert len(cases) == 3
    for case in cases:
        assert case.id in response.text
    assert "EventSource" in response.text
    assert "PatchBay" in response.text
    assert "CVE → research → failing repro → patch → mutation gate → evidence report" in response.text
    assert ".log-retry" in response.text
    assert 'status === "retry"' in response.text


def test_get_api_cases():
    """b. GET /api/cases returns 3 cases with the fields above."""
    client = TestClient(app)
    response = client.get("/api/cases")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    expected_fields = {
        "id",
        "package",
        "vulnerable_version",
        "fixed_version",
        "cwe",
        "summary",
    }
    for item in data:
        assert set(item.keys()) == expected_fields
        assert item["id"].startswith("CVE-")


def test_stream_pipeline_run_success():
    """c. GET /api/run/<first case> (stream) yields event: stage lines whose start
    stages appear in order research, brief, repro, patch, mutate, report, and
    ends with exactly one event: report containing that case id."""
    case = list_cases()[0]
    _require_site(case)
    client = TestClient(app)
    with client.stream("GET", f"/api/run/{case.id}") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")
        lines = list(response.iter_lines())

    current_event = None
    start_stages: list[str] = []
    report_events: list[dict[str, Any]] = []
    last_event_name: str | None = None

    for line in lines:
        line = line.strip()
        if not line:
            current_event = None
            continue
        if line.startswith("event: "):
            current_event = line.removeprefix("event: ").strip()
            last_event_name = current_event
        elif line.startswith("data: ") and current_event:
            payload = json.loads(line.removeprefix("data: ").strip())
            if current_event == "stage" and payload.get("status") == "start":
                start_stages.append(payload.get("stage"))
            elif current_event == "report":
                report_events.append(payload)

    assert start_stages == ["research", "brief", "repro", "patch", "mutate", "report"]
    assert len(report_events) == 1
    assert report_events[0]["case_id"] == case.id
    assert "markdown" in report_events[0]
    assert last_event_name == "report"


@pytest.mark.parametrize("bad_id", ["..%2Fetc", "CVE-0000-0000"])
def test_unknown_case_id_returns_404_and_does_not_call_pipeline(bad_id, monkeypatch):
    """d. unknown id (e.g. ../etc url-encoded and CVE-0000-0000) → 404, and
    pipeline.run is never called (monkeypatch it to raise)."""
    def fake_run(*args, **kwargs):
        raise AssertionError("pipeline.run should not be called for unknown case IDs")

    monkeypatch.setattr(pipeline, "run", fake_run)
    client = TestClient(app)
    response = client.get(f"/api/run/{bad_id}")
    assert response.status_code == 404
    assert response.headers.get("content-type", "").startswith("application/json")
    assert "error" in response.json()


def test_pipeline_refused_ends_with_refused_event(monkeypatch):
    """e. a monkeypatched pipeline.run that raises PipelineRefused("patch","nope")
    → stream ends with event: refused carrying stage "patch"."""
    case = list_cases()[0]

    def fake_run(*args, **kwargs):
        raise PipelineRefused("patch", "nope")

    monkeypatch.setattr(pipeline, "run", fake_run)
    client = TestClient(app)
    with client.stream("GET", f"/api/run/{case.id}") as response:
        assert response.status_code == 200
        lines = list(response.iter_lines())

    events: list[tuple[str, dict[str, Any]]] = []
    current_event = None
    for line in lines:
        line = line.strip()
        if not line:
            current_event = None
            continue
        if line.startswith("event: "):
            current_event = line.removeprefix("event: ").strip()
        elif line.startswith("data: ") and current_event:
            payload = json.loads(line.removeprefix("data: ").strip())
            events.append((current_event, payload))

    assert len(events) == 1
    event_name, payload = events[0]
    assert event_name == "refused"
    assert payload["stage"] == "patch"
    assert payload["reason"] == "nope"


def test_settings_always_offline_even_with_live_env(monkeypatch):
    """f. even with env LIVE=1, the Settings passed to pipeline.run has live False
    (monkeypatch pipeline.run to capture settings)."""
    monkeypatch.setenv("LIVE", "1")
    case = list_cases()[0]
    captured_settings = []

    def fake_run(case_arg, *, settings=None, **kwargs):
        captured_settings.append(settings)
        return "# Fake Report"

    monkeypatch.setattr(pipeline, "run", fake_run)
    client = TestClient(app)
    with client.stream("GET", f"/api/run/{case.id}") as response:
        assert response.status_code == 200
        list(response.iter_lines())

    assert len(captured_settings) == 1
    assert captured_settings[0] is not None
    assert captured_settings[0].live is False


def test_busy_lock_returns_429():
    """g. busy: while a run holds the lock, a second request gets 429 (you may
    acquire the module's lock directly in the test)."""
    case = list_cases()[0]
    client = TestClient(app)
    with RUN_LOCK:
        response = client.get(f"/api/run/{case.id}")
        assert response.status_code == 429
        assert response.headers.get("content-type", "").startswith("application/json")
        assert response.json() == {"error": "busy"}


def test_generic_exception_emits_error_event(monkeypatch):
    """Generic exception emits event: error with exception type name only."""
    case = list_cases()[0]

    def fake_run(*args, **kwargs):
        raise ValueError("sensitive secret details")

    monkeypatch.setattr(pipeline, "run", fake_run)
    client = TestClient(app)
    with client.stream("GET", f"/api/run/{case.id}") as response:
        assert response.status_code == 200
        lines = list(response.iter_lines())

    events: list[tuple[str, dict[str, Any]]] = []
    current_event = None
    for line in lines:
        line = line.strip()
        if not line:
            current_event = None
            continue
        if line.startswith("event: "):
            current_event = line.removeprefix("event: ").strip()
        elif line.startswith("data: ") and current_event:
            payload = json.loads(line.removeprefix("data: ").strip())
            events.append((current_event, payload))

    assert len(events) == 1
    event_name, payload = events[0]
    assert event_name == "error"
    assert payload == {"message": "ValueError"}


def test_lock_follows_pipeline_run_not_the_http_stream(monkeypatch):
    """The busy lock is held exactly while the pipeline runs, even if nobody reads the stream."""
    import threading

    from patchbay import web

    release = threading.Event()
    finished = threading.Event()

    def slow_run(case, *, settings=None, on_event=None, **kwargs):
        release.wait(5)
        finished.set()
        return "# report"

    monkeypatch.setattr(pipeline, "run", slow_run)
    case_id = list_cases()[0].id

    web.run_case_endpoint(case_id)  # response body is never iterated
    assert RUN_LOCK.locked()

    release.set()
    assert finished.wait(5)
    for _ in range(50):
        if not RUN_LOCK.locked():
            break
        threading.Event().wait(0.05)
    assert not RUN_LOCK.locked()
