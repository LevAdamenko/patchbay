"""End-to-end pipeline running stages 1 through 6 with structured event emission."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Callable

from patchbay import mutate, report
from patchbay.cases import Case, load_case
from patchbay.clients.replay import FixtureMissing
from patchbay.clients.nemotron import NemotronClient
from patchbay.clients.tavily import TavilyClient
from patchbay.config import Settings
from patchbay.evidence import Evidence, MutationEvidence, RunEvidence
from patchbay.report import MissingEvidence
from patchbay.stages import StageFailed
from patchbay.stages import brief as brief_stage
from patchbay.stages import patch as patch_stage
from patchbay.stages import repro as repro_stage
from patchbay.stages import research as research_stage


class PipelineRefused(RuntimeError):
    """Raised when the pipeline cannot complete or verification fails."""

    def __init__(self, stage: str, reason: str) -> None:
        super().__init__(f"Pipeline refused at stage '{stage}': {reason}")
        self.stage = stage
        self.reason = reason


def _reason(exc: Exception) -> str:
    if isinstance(exc, FixtureMissing):
        # Offline replay only holds the recorded happy path; any retry is a refusal.
        return f"offline replay has no recorded answer for this request ({exc})"
    return exc.reason


def _scrub_api_keys(text: str) -> str:
    """Ensure no environment API key secrets leak into event details."""
    for key, value in os.environ.items():
        if "API_KEY" in key and value and value in text:
            text = text.replace(value, "[REDACTED]")
    return text


def run(
    case_id: str | Case,
    *,
    settings: Settings | None = None,
    tavily: TavilyClient | None = None,
    nemotron: NemotronClient | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> str:
    """Run stages 1-6 for the specified case and return the generated report markdown."""
    if settings is None:
        settings = Settings()

    if isinstance(case_id, Case):
        case = case_id
    else:
        case = load_case(case_id)

    if tavily is None:
        tavily = TavilyClient(settings, namespace=case.id)
    if nemotron is None:
        nemotron = NemotronClient(settings, namespace=case.id)

    target_path = case.site / case.target
    if not target_path.is_file():
        raise FileNotFoundError(
            f"Target file missing: {target_path}; run: python scripts/fetch_cases.py"
        )
    target_text = target_path.read_text(encoding="utf-8")

    def emit(stage: str, status: str, detail: str, evidence_hash: str | None = None) -> None:
        if on_event is not None:
            on_event({
                "stage": stage,
                "status": status,
                "detail": _scrub_api_keys(detail),
                "evidence_hash": evidence_hash,
            })

    # Stage 1: Research
    emit("research", "start", f"Searching advisories for {case.id}")
    try:
        sources = research_stage.run(case, tavily)
        emit("research", "ok", f"Found {len(sources)} sources", None)
    except (StageFailed, FixtureMissing) as exc:
        reason = _reason(exc)
        emit("research", "fail", reason, None)
        raise PipelineRefused("research", reason) from exc

    # Stage 2: Brief
    emit("brief", "start", f"Generating vulnerability brief for {case.id}")
    try:
        brief = brief_stage.run(case, sources, target_text, nemotron)
        emit("brief", "ok", f"Brief generated ({brief.cwe})", None)
    except (StageFailed, FixtureMissing) as exc:
        reason = _reason(exc)
        emit("brief", "fail", reason, None)
        raise PipelineRefused("brief", reason) from exc

    # Stage 3: Repro
    emit("repro", "start", f"Writing reproduction test for {case.id}")
    try:
        test_code, red_run = repro_stage.run(case, brief, target_text, nemotron)
        emit(
            "repro",
            "ok",
            f"Repro test confirmed RED ({red_run.outcome})",
            red_run.log_sha256,
        )
    except (StageFailed, FixtureMissing) as exc:
        reason = _reason(exc)
        emit("repro", "fail", reason, None)
        raise PipelineRefused("repro", reason) from exc

    # Stage 4 & 5: Patch + Mutation gate feedback loop
    gate = lambda d: mutate.run_gate(
        case.root,
        f"site/{case.target}",
        target_text,
        d,
        {"test_cve_repro.py": test_code},
        "test_cve_repro.py",
        case.repro_timeout,
    )

    def on_gate(result: mutate.GateResult, will_retry: bool) -> None:
        emit("mutate", "start", f"Running mutation gate on {case.target}")
        if will_retry:
            n = len(result.survivors)
            emit(
                "mutate",
                "retry",
                f"Mutation gate failed ({result.score:.0%}); {n} surviving mutants sent back to Nemotron",
            )
            emit("patch", "start", "Retrying patch with mutation-gate feedback")
        else:
            emit(
                "mutate",
                "fail",
                f"Mutation gate failed with score {result.score:.0%}",
            )

    emit("patch", "start", f"Generating and testing patch for {case.id}")
    try:
        diff, green_run, regression_run, gate_result = patch_stage.run(
            case,
            brief,
            test_code,
            target_text,
            nemotron,
            gate=gate,
            on_gate=on_gate,
        )
        assert gate_result is not None
        emit(
            "patch",
            "ok",
            "Patch passed repro and regression tests",
            green_run.log_sha256,
        )
        emit("mutate", "start", f"Running mutation gate on {case.target}")
        emit("mutate", "ok", f"Mutation gate passed ({gate_result.score:.0%})", None)
    except (StageFailed, FixtureMissing) as exc:
        reason = _reason(exc)
        if isinstance(exc, StageFailed) and reason.startswith("Mutation gate failed"):
            raise PipelineRefused("mutate", reason) from exc
        emit("patch", "fail", reason, None)
        raise PipelineRefused("patch", reason) from exc

    # Stage 6: Report
    emit("report", "start", f"Compiling evidence and rendering report for {case.id}")
    try:
        red_evidence = RunEvidence.from_result("red", red_run, test_code, None)
        green_evidence = RunEvidence.from_result("green", green_run, test_code, diff)
        regression_path = case.root / "tests/test_regression.py"
        regression_test_text = regression_path.read_text(encoding="utf-8")
        regression_evidence = RunEvidence.from_result(
            "regression", regression_run, regression_test_text, diff
        )
        mutation_evidence = MutationEvidence.from_gate(gate_result)

        evidence = Evidence(
            case_id=case.id,
            cve=case.id,
            package=case.package,
            sources=sources,
            brief=brief,
            test_code=test_code,
            diff=diff,
            red=red_evidence,
            green=green_evidence,
            regression=regression_evidence,
            mutation=mutation_evidence,
        )
        report_md = report.render(evidence)
        emit("report", "ok", "Report rendered successfully", evidence.digest())
        return report_md
    except MissingEvidence as exc:
        emit("report", "fail", str(exc), None)
        raise PipelineRefused("report", str(exc)) from exc
