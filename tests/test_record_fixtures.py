"""Tests for scripts/record_fixtures.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from patchbay import pipeline
from patchbay.cases import Case, load_case
from patchbay.config import Settings
from scripts.record_fixtures import main, record_case

FAKE_NEBIUS_KEY = "sk-test-SECRET123"
FAKE_TAVILY_KEY = "tvly-test-SECRET456"


def _make_settings(tmp_path: Path, *, live: bool = True) -> Settings:
    settings = Settings()
    settings.live = live
    settings.fixtures_dir = tmp_path / "fixtures"
    settings.nebius_api_key = FAKE_NEBIUS_KEY
    settings.tavily_api_key = FAKE_TAVILY_KEY
    return settings


def _make_tavily_mock(case: Case):
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        calls.append(data)
        results = [
            {
                "url": url,
                "title": f"{case.id} advisory",
                "content": case.summary,
                "retrieved_at": "2026-10-15T00:00:00Z",
            }
            for url in case.advisory_urls
        ]
        return httpx.Response(200, json={"results": results})

    return httpx.MockTransport(handler), calls


def _make_nemotron_success_mock(case: Case):
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        calls.append(data)
        messages = data.get("messages", [])
        user_content = messages[0]["content"] if messages else ""

        if "You are a security vulnerability analyst." in user_content:
            fields = ("cwe", "affected_function", "trigger", "expected_behaviour")
            citations = {
                field: case.advisory_urls[i % len(case.advisory_urls)]
                for i, field in enumerate(fields)
            }
            brief_dict = {
                "cwe": case.cwe,
                "affected_function": case.summary,
                "trigger": case.summary,
                "expected_behaviour": case.summary,
                "citations": citations,
            }
            content = json.dumps(brief_dict, indent=2, sort_keys=True)
        elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
            repro_path = case.root / "reference" / "test_cve_repro.py"
            content = "```python\n" + repro_path.read_text(encoding="utf-8") + "\n```"
        elif "You are a security engineer writing a patch for a vulnerability" in user_content:
            patch_path = case.root / "reference" / "fix.patch"
            content = "```diff\n" + patch_path.read_text(encoding="utf-8") + "\n```"
        else:
            raise ValueError(f"Unexpected prompt in Nemotron mock: {user_content[:100]}...")

        response_body = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": content,
                    }
                }
            ]
        }
        return httpx.Response(200, json=response_body)

    return httpx.MockTransport(handler), calls


def test_record_case_success(tmp_path: Path):
    """Test a: record_case returns True; fixtures/<case>/ has nemotron-*.json and tavily-*.json;

    no file contains 'synthetic', the fake key strings, or 'Bearer '; offline pipeline.run returns report.
    """
    case = load_case("CVE-2023-32681")
    settings = _make_settings(tmp_path)

    tavily_transport, tavily_calls = _make_tavily_mock(case)
    nemotron_transport, nemotron_calls = _make_nemotron_success_mock(case)

    ok = record_case(
        case,
        settings,
        attempts=3,
        tavily_transport=tavily_transport,
        nemotron_transport=nemotron_transport,
    )
    assert ok is True

    case_fixtures = settings.fixtures_dir / case.id
    assert case_fixtures.is_dir()

    nemotron_files = list(case_fixtures.glob("nemotron-*.json"))
    tavily_files = list(case_fixtures.glob("tavily-*.json"))

    assert len(nemotron_files) > 0, "Expected at least one nemotron fixture"
    assert len(tavily_files) > 0, "Expected at least one tavily fixture"

    all_files = nemotron_files + tavily_files
    for file_path in all_files:
        text = file_path.read_text(encoding="utf-8")
        assert "synthetic" not in text, f"File {file_path.name} contains 'synthetic'"
        assert FAKE_NEBIUS_KEY not in text, f"File {file_path.name} contains fake Nebius key"
        assert FAKE_TAVILY_KEY not in text, f"File {file_path.name} contains fake Tavily key"
        assert "Bearer " not in text, f"File {file_path.name} contains 'Bearer '"

    # Verify offline replay works
    offline_settings = Settings()
    offline_settings.live = False
    offline_settings.fixtures_dir = settings.fixtures_dir

    report = pipeline.run(case, settings=offline_settings)
    assert report, "Expected non-empty report from offline pipeline"
    assert "Evidence digest" in report


def test_record_case_all_attempts_fail(tmp_path: Path):
    """Test b: all attempts fail (model returns garbage text): returns False and a pre-existing

    sentinel fixture file in fixtures/<case>/ is unchanged; Tavily mock was hit exactly 2 times
    total across 3 attempts (one per distinct query).
    """
    case = load_case("CVE-2023-32681")
    settings = _make_settings(tmp_path)

    case_fixtures = settings.fixtures_dir / case.id
    case_fixtures.mkdir(parents=True, exist_ok=True)
    sentinel_path = case_fixtures / "sentinel.json"
    sentinel_content = '{\n  "sentinel": "should_remain_unchanged"\n}\n'
    sentinel_path.write_text(sentinel_content, encoding="utf-8")

    tavily_transport, tavily_calls = _make_tavily_mock(case)

    # Nemotron returns garbage text that fails brief parsing
    def nemotron_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "I am unable to analyze this vulnerability.",
                        }
                    }
                ]
            },
        )

    nemotron_transport = httpx.MockTransport(nemotron_handler)

    ok = record_case(
        case,
        settings,
        attempts=3,
        tavily_transport=tavily_transport,
        nemotron_transport=nemotron_transport,
    )
    assert ok is False

    # Sentinel must be completely unchanged
    assert sentinel_path.is_file()
    assert sentinel_path.read_text(encoding="utf-8") == sentinel_content

    # Tavily mock was hit exactly 2 times total across 3 attempts (1 per distinct query)
    assert len(tavily_calls) == 2, f"Expected exactly 2 Tavily hits, got {len(tavily_calls)}"


def test_record_case_retry_succeeds_cleans_nemotron(tmp_path: Path):
    """Test c: first attempt fails, second succeeds: returns True, Tavily hits == 2,

    and only nemotron fixtures from the successful attempt remain (offline replay works).
    """
    case = load_case("CVE-2023-32681")
    settings = _make_settings(tmp_path)

    tavily_transport, tavily_calls = _make_tavily_mock(case)

    # Model fails on attempt 1, succeeds on attempt 2
    attempt_counter = 0

    def nemotron_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempt_counter
        data = json.loads(request.content)
        messages = data.get("messages", [])
        user_content = messages[0]["content"] if messages else ""

        # First prompt of brief: track which attempt this is
        if len(messages) == 1 and "You are a security vulnerability analyst." in user_content:
            attempt_counter += 1

        if attempt_counter == 1:
            # Return garbage for attempt 1
            return httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": "Garbage reply"}}]},
            )

        # Attempt 2: return valid responses
        if "You are a security vulnerability analyst." in user_content:
            fields = ("cwe", "affected_function", "trigger", "expected_behaviour")
            citations = {
                field: case.advisory_urls[i % len(case.advisory_urls)]
                for i, field in enumerate(fields)
            }
            brief_dict = {
                "cwe": case.cwe,
                "affected_function": case.summary,
                "trigger": case.summary,
                "expected_behaviour": case.summary,
                "citations": citations,
            }
            content = json.dumps(brief_dict, indent=2, sort_keys=True)
        elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
            repro_path = case.root / "reference" / "test_cve_repro.py"
            content = "```python\n" + repro_path.read_text(encoding="utf-8") + "\n```"
        elif "You are a security engineer writing a patch for a vulnerability" in user_content:
            patch_path = case.root / "reference" / "fix.patch"
            content = "```diff\n" + patch_path.read_text(encoding="utf-8") + "\n```"
        else:
            raise ValueError(f"Unexpected prompt: {user_content[:100]}...")

        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": content}}]},
        )

    nemotron_transport = httpx.MockTransport(nemotron_handler)

    ok = record_case(
        case,
        settings,
        attempts=3,
        tavily_transport=tavily_transport,
        nemotron_transport=nemotron_transport,
    )
    assert ok is True

    # Tavily hits == 2 across attempts
    assert len(tavily_calls) == 2, f"Expected exactly 2 Tavily hits, got {len(tavily_calls)}"

    case_fixtures = settings.fixtures_dir / case.id
    nemotron_files = list(case_fixtures.glob("nemotron-*.json"))
    # Exactly 3 nemotron fixtures (brief, repro, patch) from attempt 2; attempt 1 fixtures were cleaned up
    assert len(nemotron_files) == 3, f"Expected 3 nemotron fixtures, got {len(nemotron_files)}"

    # Offline replay works
    offline_settings = Settings()
    offline_settings.live = False
    offline_settings.fixtures_dir = settings.fixtures_dir

    report = pipeline.run(case, settings=offline_settings)
    assert report, "Expected offline replay to succeed and return report"
    assert "Evidence digest" in report


def test_main_refuses_when_live_is_false(monkeypatch: pytest.MonkeyPatch):
    """Test d: main refuses with exit code 2 when live is False."""
    monkeypatch.setenv("LIVE", "0")
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)

    exit_code = main([])
    assert exit_code == 2

    # Also test via subprocess to verify CLI exit code
    env = {**os.environ, "LIVE": "0"}
    env.pop("NEBIUS_API_KEY", None)
    env.pop("TAVILY_API_KEY", None)
    proc = subprocess.run(
        [sys.executable, "scripts/record_fixtures.py"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 2
    assert "Refusing to record" in proc.stderr or "Refusing to record" in proc.stdout


def test_record_case_aborts_on_secret_leak(tmp_path: Path):
    """Test security scan: if response contains API key, 'Bearer ', or 'api_key',

    record_case aborts, returns False, and fixtures are untouched.
    """
    case = load_case("CVE-2023-32681")
    settings = _make_settings(tmp_path)

    case_fixtures = settings.fixtures_dir / case.id
    case_fixtures.mkdir(parents=True, exist_ok=True)
    sentinel = case_fixtures / "sentinel.txt"
    sentinel.write_text("untouched", encoding="utf-8")

    tavily_transport, _ = _make_tavily_mock(case)

    # Nemotron returns a patch with the secret key leaked in a comment
    def nemotron_handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        messages = data.get("messages", [])
        user_content = messages[0]["content"] if messages else ""

        if "You are a security vulnerability analyst." in user_content:
            fields = ("cwe", "affected_function", "trigger", "expected_behaviour")
            citations = {
                field: case.advisory_urls[i % len(case.advisory_urls)]
                for i, field in enumerate(fields)
            }
            brief_dict = {
                "cwe": case.cwe,
                "affected_function": case.summary,
                "trigger": case.summary,
                "expected_behaviour": case.summary,
                "citations": citations,
            }
            content = json.dumps(brief_dict)
        elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
            repro_path = case.root / "reference" / "test_cve_repro.py"
            # Leak the secret key into the repro test text
            content = f"```python\n# {FAKE_NEBIUS_KEY}\n" + repro_path.read_text(encoding="utf-8") + "\n```"
        elif "You are a security engineer writing a patch for a vulnerability" in user_content:
            patch_path = case.root / "reference" / "fix.patch"
            content = "```diff\n" + patch_path.read_text(encoding="utf-8") + "\n```"
        else:
            raise ValueError(f"Unexpected prompt: {user_content[:100]}...")

        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": content}}]},
        )

    nemotron_transport = httpx.MockTransport(nemotron_handler)

    ok = record_case(
        case,
        settings,
        attempts=1,
        tavily_transport=tavily_transport,
        nemotron_transport=nemotron_transport,
    )
    assert ok is False
    # Sentinel must still be there, and no recorded json files in case_fixtures
    assert sentinel.is_file()
    assert sentinel.read_text(encoding="utf-8") == "untouched"
    assert list(case_fixtures.glob("*.json")) == []


def test_record_fixtures_with_prepopulated_tavily_cache_and_failed_transcripts(tmp_path: Path):
    """With a pre-populated --tavily-cache, live Tavily transport receives ZERO calls;

    a failed case writes failed-attempt transcripts and they contain no fake key.
    """
    case = load_case("CVE-2023-32681")
    settings = _make_settings(tmp_path)
    cache_dir = tmp_path / "cache"

    # 1. Populate the cache with live tavily mock
    tavily_transport, tavily_calls = _make_tavily_mock(case)
    nemotron_transport, _ = _make_nemotron_success_mock(case)

    ok = record_case(
        case,
        settings,
        attempts=1,
        tavily_transport=tavily_transport,
        nemotron_transport=nemotron_transport,
        tavily_cache_dir=cache_dir,
    )
    assert ok is True
    assert len(tavily_calls) == 2
    cached_tavily_files = list((cache_dir / case.id).glob("tavily-*.json"))
    assert len(cached_tavily_files) > 0, "Expected tavily fixtures to be cached"

    # 2. Run with pre-populated cache and failing nemotron:
    # Live Tavily transport must receive ZERO calls.
    tavily_transport2, tavily_calls2 = _make_tavily_mock(case)

    def nemotron_fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "Analysis refusal"}}]},
        )

    nemotron_transport2 = httpx.MockTransport(nemotron_fail_handler)

    settings2 = _make_settings(tmp_path / "run2")
    ok2 = record_case(
        case,
        settings2,
        attempts=1,
        tavily_transport=tavily_transport2,
        nemotron_transport=nemotron_transport2,
        tavily_cache_dir=cache_dir,
    )
    assert ok2 is False
    assert len(tavily_calls2) == 0, f"Expected ZERO Tavily calls, got {len(tavily_calls2)}"

    # Check failed-attempt transcripts exist and contain no fake keys
    failed_dir = cache_dir / case.id / "failed-attempt-1"
    assert failed_dir.is_dir(), f"Expected {failed_dir} to exist"
    failed_files = list(failed_dir.glob("nemotron-*.json"))
    assert len(failed_files) > 0, "Expected nemotron transcripts in failed-attempt-1"

    for ff in failed_files:
        content = ff.read_text(encoding="utf-8")
        assert FAKE_NEBIUS_KEY not in content
        assert FAKE_TAVILY_KEY not in content
        assert "Bearer " not in content


