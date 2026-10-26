"""Unit and integration tests for the end-to-end PatchBay pipeline."""

from __future__ import annotations

import json
from typing import Any

import pytest

from patchbay import pipeline
from patchbay.cases import Case, list_cases, load_case
from patchbay.config import Settings
from patchbay.pipeline import PipelineRefused


def _require_site(case: Case) -> None:
    if not (case.site / case.target).is_file():
        pytest.skip(f"{case.id} site/ is not fetched; run: python scripts/fetch_cases.py")


def _synthetic_fixtures(case: Case, tmp_path):
    """Build synthetic fixtures in tmp: tests that edit or fake responses must not
    depend on whether fixtures/ holds live recordings or synthetic ones."""
    from scripts.build_offline_fixtures import build_fixtures_for_case

    fixtures = tmp_path / "fixtures"
    build_fixtures_for_case(case, fixtures)
    return fixtures


@pytest.mark.parametrize("case", list_cases(), ids=lambda c: c.id)
def test_pipeline_replayed_fixtures_produces_report_in_stage_order(case, monkeypatch):
    _require_site(case)
    monkeypatch.setenv("LIVE", "0")

    events: list[dict[str, Any]] = []
    report = pipeline.run(case, on_event=events.append)

    assert report
    assert report.startswith(f"# {case.id}: {case.package} fix")
    assert f"Case: `{case.id}`." in report
    assert "Mutation score:" in report
    assert "Evidence digest" in report

    # Verify events are emitted in exact stage order
    stages_started = [e["stage"] for e in events if e["status"] == "start"]
    expected_stages = ["research", "brief", "repro", "patch", "mutate", "report"]
    assert stages_started == expected_stages

    stages_ok = [e["stage"] for e in events if e["status"] == "ok"]
    assert stages_ok == expected_stages


def test_pipeline_wrong_patch_causes_pipeline_refused(monkeypatch, tmp_path):
    case = load_case("CVE-2023-32681")
    _require_site(case)
    monkeypatch.setenv("LIVE", "0")
    monkeypatch.setenv("FIXTURES_DIR", str(_synthetic_fixtures(case, tmp_path)))

    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")

    class FakePatchNemotron:
        def __init__(self) -> None:
            self.calls = 0

        def chat(
            self,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]] | None = None,
            response_format: dict[str, Any] | None = None,
            temperature: float = 0.2,
        ) -> dict[str, Any]:
            self.calls += 1
            user_content = messages[0]["content"] if messages else ""

            if "You are a security vulnerability analyst." in user_content:
                brief = {
                    "cwe": case.cwe,
                    "affected_function": case.summary,
                    "trigger": case.summary,
                    "expected_behaviour": case.summary,
                    "citations": {
                        "cwe": case.advisory_urls[0],
                        "affected_function": case.advisory_urls[0],
                        "trigger": case.advisory_urls[0],
                        "expected_behaviour": case.advisory_urls[0],
                    },
                }
                content = json.dumps(brief)
            elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
                content = f"```python\n{ref_test}\n```"
            else:
                # Patch prompt: return a wrong/no-op diff that leaves repro failing
                content = (
                    "```diff\n"
                    "--- a/requests/sessions.py\n"
                    "+++ b/requests/sessions.py\n"
                    "@@ -1,3 +1,4 @@\n"
                    "+# no-op comment\n"
                    ' """\n'
                    " requests.sessions\n"
                    "```"
                )

            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": content,
                        }
                    }
                ]
            }

        @property
        def _fixture_dir(self):
            return Settings().fixtures_dir / case.id

    fake_client = FakePatchNemotron()

    with pytest.raises(PipelineRefused) as exc_info:
        pipeline.run(case, nemotron=fake_client)

    assert exc_info.value.stage == "patch"
    assert "Patch stage failed after 4 attempts" in exc_info.value.reason


def test_pipeline_scrubs_api_key_from_events(monkeypatch):
    case = load_case("CVE-2023-32681")
    _require_site(case)
    monkeypatch.setenv("LIVE", "0")
    monkeypatch.setenv("FOO_API_KEY", "secret123")

    events: list[dict[str, Any]] = []
    pipeline.run(case, on_event=events.append)

    assert events
    for event in events:
        for field, value in event.items():
            assert "secret123" not in str(value), f"Secret leaked in event {field}: {value}"


def test_replay_miss_on_retry_is_a_clean_refusal(tmp_path, monkeypatch):
    """A patch fixture that fails verification makes the stage retry; offline replay
    has no answer for the retry, which must surface as PipelineRefused, not a crash."""
    import json

    from patchbay.cases import load_case
    from patchbay.config import Settings
    from patchbay.pipeline import PipelineRefused, run

    case = load_case("CVE-2024-24762")
    if not (case.site / case.target).is_file():
        pytest.skip("run scripts/fetch_cases.py first")
    monkeypatch.setenv("LIVE", "0")
    settings = Settings()
    settings.live = False
    fixtures = _synthetic_fixtures(case, tmp_path)
    settings.fixtures_dir = fixtures
    for path in (fixtures / case.id).glob("nemotron-*.json"):
        data = json.loads(path.read_text())
        message = data["response"]["choices"][0]["message"]
        if message["content"].startswith("```diff"):
            lines = message["content"].split("\n")
            minus = next(line for line in lines if line.startswith("-QUOTED"))
            message["content"] = "\n".join(
                "+" + minus[1:] if line.startswith("+QUOTED") else line for line in lines
            )
            path.write_text(json.dumps(data))
    events = []
    with pytest.raises(PipelineRefused) as refused:
        run(case.id, settings=settings, on_event=events.append)
    assert refused.value.stage == "patch"
    assert events[-1]["status"] == "fail"
    assert all(e["stage"] != "report" for e in events)


def test_pipeline_mutation_gate_retry_emits_events_and_produces_report(monkeypatch, tmp_path):
    from patchbay.mutate import GateResult, Mutant, run_gate as real_run_gate

    case = load_case("CVE-2024-24762")
    _require_site(case)
    monkeypatch.setenv("LIVE", "0")
    monkeypatch.setenv("FIXTURES_DIR", str(_synthetic_fixtures(case, tmp_path)))

    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")

    class FakeRetryNemotron:
        def __init__(self) -> None:
            self.patch_calls = 0

        def chat(
            self,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]] | None = None,
            response_format: dict[str, Any] | None = None,
            temperature: float = 0.2,
        ) -> dict[str, Any]:
            user_content = messages[0]["content"] if messages else ""
            if "You are a security vulnerability analyst." in user_content:
                brief = {
                    "cwe": case.cwe,
                    "affected_function": case.summary,
                    "trigger": case.summary,
                    "expected_behaviour": case.summary,
                    "citations": {
                        "cwe": case.advisory_urls[0],
                        "affected_function": case.advisory_urls[0],
                        "trigger": case.advisory_urls[0],
                        "expected_behaviour": case.advisory_urls[0],
                    },
                }
                content = json.dumps(brief)
            elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
                content = f"```python\n{ref_test}\n```"
            else:
                self.patch_calls += 1
                content = f"```diff\n{ref_patch}\n```"

            return {"choices": [{"message": {"role": "assistant", "content": content}}]}

    gate_calls = 0

    def fake_run_gate(workdir, target, original, diff, test_files, test_path, timeout):
        nonlocal gate_calls
        gate_calls += 1
        if gate_calls == 1:
            return GateResult(
                passed=False,
                reversal_killed=1,
                reversal_total=1,
                operator_killed=0,
                operator_total=2,
                score=1 / 3,
                survivors=[Mutant("operator", "flip comparison ==", 1, original)],
                results=[],
            )
        return real_run_gate(workdir, target, original, diff, test_files, test_path, timeout)

    monkeypatch.setattr(pipeline.mutate, "run_gate", fake_run_gate)

    events: list[dict[str, Any]] = []
    report_md = pipeline.run(case, nemotron=FakeRetryNemotron(), on_event=events.append)

    assert report_md.startswith(f"# {case.id}: {case.package} fix")
    stage_status_pairs = [(e["stage"], e["status"]) for e in events]
    assert ("mutate", "retry") in stage_status_pairs
    retry_idx = stage_status_pairs.index(("mutate", "retry"))
    assert stage_status_pairs[retry_idx + 1] == ("patch", "start")
    assert ("mutate", "ok") in stage_status_pairs[retry_idx + 2 :]
    assert ("report", "ok") in stage_status_pairs


def test_pipeline_mutation_gate_exhausted_refuses_at_mutate(monkeypatch, tmp_path):
    from patchbay.mutate import GateResult, Mutant

    case = load_case("CVE-2024-24762")
    _require_site(case)
    monkeypatch.setenv("LIVE", "0")
    monkeypatch.setenv("FIXTURES_DIR", str(_synthetic_fixtures(case, tmp_path)))

    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")

    class FakeExhaustedNemotron:
        def chat(
            self,
            messages: list[dict[str, Any]],
            tools: list[dict[str, Any]] | None = None,
            response_format: dict[str, Any] | None = None,
            temperature: float = 0.2,
        ) -> dict[str, Any]:
            user_content = messages[0]["content"] if messages else ""
            if "You are a security vulnerability analyst." in user_content:
                brief = {
                    "cwe": case.cwe,
                    "affected_function": case.summary,
                    "trigger": case.summary,
                    "expected_behaviour": case.summary,
                    "citations": {
                        "cwe": case.advisory_urls[0],
                        "affected_function": case.advisory_urls[0],
                        "trigger": case.advisory_urls[0],
                        "expected_behaviour": case.advisory_urls[0],
                    },
                }
                content = json.dumps(brief)
            elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
                content = f"```python\n{ref_test}\n```"
            else:
                content = f"```diff\n{ref_patch}\n```"
            return {"choices": [{"message": {"role": "assistant", "content": content}}]}

    def always_fail_gate(workdir, target, original, diff, test_files, test_path, timeout):
        return GateResult(
            passed=False,
            reversal_killed=1,
            reversal_total=1,
            operator_killed=0,
            operator_total=2,
            score=0.5,
            survivors=[Mutant("operator", "flip comparison ==", 1, original)],
            results=[],
        )

    monkeypatch.setattr(pipeline.mutate, "run_gate", always_fail_gate)

    events: list[dict[str, Any]] = []
    with pytest.raises(PipelineRefused) as exc_info:
        pipeline.run(case, nemotron=FakeExhaustedNemotron(), on_event=events.append)

    assert exc_info.value.stage == "mutate"
    assert exc_info.value.reason == "Mutation gate failed with score 50%"
    assert events[-1]["stage"] == "mutate"
    assert events[-1]["status"] == "fail"
    assert events[-1]["detail"] == "Mutation gate failed with score 50%"
