"""Deterministic evidence validation and PR-markdown rendering."""

from __future__ import annotations

from .evidence import Evidence, MutationEvidence, sha256_text
from .mutate import gate_passes


class MissingEvidence(ValueError):
    pass


_BRIEF_FIELDS = ("cwe", "affected_function", "trigger", "expected_behaviour")


def _missing(reason: str) -> None:
    raise MissingEvidence(reason)


def _nonempty(value: object, name: str) -> None:
    if value is None or (isinstance(value, str) and not value.strip()):
        _missing(f"missing {name}")


def _validate_run(run: object, name: str) -> None:
    if run is None:
        _missing(f"missing {name}")
    for field in ("label", "outcome", "log_sha256", "test_sha256", "duration"):
        _nonempty(getattr(run, field, None), f"{name}.{field}")


def _validate_mutation(mutation: MutationEvidence | None) -> None:
    if mutation is None:
        _missing("missing mutation")
    assert mutation is not None
    for name in ("reversal_killed", "reversal_total", "operator_killed", "operator_total"):
        value = getattr(mutation, name)
        if not isinstance(value, int) or value < 0:
            _missing(f"invalid mutation {name}")
    if mutation.reversal_killed > mutation.reversal_total or mutation.operator_killed > mutation.operator_total:
        _missing("mutation kill counts are inconsistent")
    total = mutation.reversal_total + mutation.operator_total
    expected_score = (mutation.reversal_killed + mutation.operator_killed) / total if total else 1.0
    if mutation.score != expected_score:
        _missing("mutation score is inconsistent")
    expected_passed = gate_passes(
        mutation.reversal_killed, mutation.reversal_total, mutation.operator_killed, mutation.operator_total
    )
    if not mutation.passed or mutation.passed != expected_passed:
        _missing("mutation gate did not pass")
    if len(mutation.survivors) != total - mutation.reversal_killed - mutation.operator_killed:
        _missing("mutation survivor count is inconsistent")
    if any(not survivor.strip() for survivor in mutation.survivors):
        _missing("blank mutation survivor")


def _validate(evidence: Evidence | None) -> None:
    if evidence is None:
        _missing("missing evidence")
    assert evidence is not None
    for field in ("case_id", "cve", "package", "test_code", "diff"):
        _nonempty(getattr(evidence, field, None), field)
    if not evidence.sources:
        _missing("missing sources")
    source_urls = set()
    for source in evidence.sources:
        if source is None:
            _missing("missing source")
        for field in ("url", "title", "snippet", "retrieved_at"):
            _nonempty(getattr(source, field, None), f"source.{field}")
        source_urls.add(source.url)
    if evidence.brief is None:
        _missing("missing brief")
    for field in _BRIEF_FIELDS:
        _nonempty(getattr(evidence.brief, field, None), f"brief.{field}")
        citation = evidence.brief.citations.get(field) if evidence.brief.citations else None
        if not citation:
            _missing(f"missing citation for brief.{field}")
        if citation not in source_urls:
            _missing(f"citation URL not in sources for brief.{field}")
    _validate_run(evidence.red, "red")
    _validate_run(evidence.green, "green")
    _validate_run(evidence.regression, "regression")
    if evidence.red.outcome not in {"assertion", "timeout"} or evidence.red.error_kind is not None:
        _missing("red run is not a valid repro failure")
    if evidence.green.outcome != "passed":
        _missing("green run did not pass")
    if evidence.regression.outcome != "passed":
        _missing("regression run did not pass")
    test_hash = sha256_text(evidence.test_code)
    if evidence.red.test_sha256 != test_hash or evidence.green.test_sha256 != test_hash:
        _missing("red/green test hash does not match test code")
    patch_hash = sha256_text(evidence.diff)
    if evidence.green.patch_sha256 != patch_hash:
        _missing("green patch hash does not match diff")
    if evidence.regression.patch_sha256 != patch_hash:
        _missing("regression run was not on the patched code")
    if evidence.red.patch_sha256 is not None:
        _missing("red run must not contain a patch hash")
    _validate_mutation(evidence.mutation)


def render(evidence: Evidence | None) -> str:
    """Validate complete evidence and return a self-contained PR description."""
    _validate(evidence)
    assert evidence is not None
    brief = evidence.brief
    source_links = "; ".join(f"[{source.title}]({source.url})" for source in evidence.sources)
    cited = "\n".join(
        f"- **{field.replace('_', ' ')}:** {getattr(brief, field)} "
        f"([source]({brief.citations[field]}))"
        for field in _BRIEF_FIELDS
    )
    runs = (evidence.red, evidence.green, evidence.regression)
    rows = "\n".join(
        f"| {run.label} | {run.outcome} | {run.error_kind or '—'} | {run.test_sha256} | "
        f"{run.patch_sha256 or '—'} | {run.log_sha256} | {run.duration:.3f}s |"
        for run in runs
    )
    mutation = evidence.mutation
    survivors = ", ".join(mutation.survivors) if mutation.survivors else "None"
    return f"""# {evidence.cve}: {evidence.package} fix

Case: `{evidence.case_id}`. Sources: {source_links}

## CVE summary

{cited}

## Reproduction test

```python
{evidence.test_code.rstrip()}
```

## Patch

```diff
{evidence.diff.rstrip()}
```

## Evidence

| Run | Outcome | Error kind | Test SHA-256 | Patch SHA-256 | Log SHA-256 | Duration |
| --- | --- | --- | --- | --- | --- | --- |
{rows}

Mutation score: **{mutation.score:.0%}** ({mutation.reversal_killed}/{mutation.reversal_total} hunk reversals killed; {mutation.operator_killed}/{mutation.operator_total} operator mutants killed).<br>
Survivors: {survivors}

Evidence digest (SHA-256): `{evidence.digest()}`
"""
