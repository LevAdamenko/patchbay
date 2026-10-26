from dataclasses import replace

import pytest

from patchbay.evidence import Evidence, MutationEvidence, RunEvidence, Source, VulnBrief, sha256_text
from patchbay.report import MissingEvidence, render


TEST = "def test_repro():\n    assert True\n"
DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n"
SOURCE = Source("https://example.test/cve", "Advisory", "A concise advisory.", "2026-10-13T00:00:00Z")
BRIEF = VulnBrief("CWE-20", "parse_key", "bad key", "reject bad key", {name: SOURCE.url for name in ("cwe", "affected_function", "trigger", "expected_behaviour")})
RED = RunEvidence("red", "assertion", None, "a" * 64, sha256_text(TEST), None, 0.1)
GREEN = RunEvidence("green", "passed", None, "b" * 64, sha256_text(TEST), sha256_text(DIFF), 0.1)
REGRESSION = RunEvidence("regression", "passed", None, "c" * 64, "d" * 64, sha256_text(DIFF), 0.1)
MUTATION = MutationEvidence(1, 1, 4, 5, 5 / 6, True, ("surviving alternative",))


def valid() -> Evidence:
    return Evidence("toy", "CVE-2026-0001", "toylib", (SOURCE,), BRIEF, TEST, DIFF, RED, GREEN, REGRESSION, MUTATION)


def test_complete_evidence_renders_hashes_and_links():
    report = render(valid())
    assert SOURCE.url in report
    assert sha256_text(TEST) in report
    assert sha256_text(DIFF) in report
    assert valid().digest() in report


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        replace(valid(), case_id=""), replace(valid(), cve=""), replace(valid(), package=""),
        replace(valid(), sources=()), replace(valid(), test_code=""), replace(valid(), diff=""),
        replace(valid(), brief=None), replace(valid(), red=None), replace(valid(), green=None),
        replace(valid(), regression=None), replace(valid(), mutation=None),
        replace(valid(), brief=replace(BRIEF, cwe="")),
        replace(valid(), brief=replace(BRIEF, citations={key: value for key, value in BRIEF.citations.items() if key != "trigger"})),
        replace(valid(), brief=replace(BRIEF, citations={**BRIEF.citations, "cwe": "https://other.test"})),
        replace(valid(), sources=(replace(SOURCE, title=""),)),
        replace(valid(), red=replace(RED, outcome="error")), replace(valid(), red=replace(RED, error_kind="ImportError")),
        replace(valid(), green=replace(GREEN, outcome="assertion")), replace(valid(), regression=replace(REGRESSION, outcome="error")),
        replace(valid(), green=replace(GREEN, test_sha256="x")), replace(valid(), green=replace(GREEN, patch_sha256="x")),
        replace(valid(), red=replace(RED, patch_sha256="x")),
        replace(valid(), regression=replace(REGRESSION, patch_sha256=None)),
        replace(valid(), mutation=replace(MUTATION, passed=False)),
        replace(valid(), mutation=replace(MUTATION, operator_killed=6)),
        replace(valid(), mutation=replace(MUTATION, score=1.0)),
        replace(valid(), mutation=replace(MUTATION, survivors=())),
    ],
)
def test_missing_or_inconsistent_evidence_is_rejected(evidence):
    with pytest.raises(MissingEvidence):
        render(evidence)
