"""Unit tests for pipeline stages."""

from __future__ import annotations

import json
from typing import Any

import pytest

from patchbay.cases import Case, load_case
from patchbay.evidence import Source, VulnBrief
from patchbay.stages import StageFailed
from patchbay.stages import brief as brief_stage
from patchbay.stages import patch as patch_stage
from patchbay.stages import repro as repro_stage


def _require_site(case: Case) -> None:
    if not (case.site / case.target).is_file():
        pytest.skip(f"{case.id} site/ is not fetched; run: python scripts/fetch_cases.py")


def _nemotron_response(content: str) -> dict[str, Any]:
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


class FakeNemotron:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        self.calls.append({
            "messages": messages,
            "tools": tools,
            "response_format": response_format,
        })
        if not self.responses:
            raise RuntimeError("No more fake responses configured")
        return self.responses.pop(0)


# =========================================================================
# Stage 2: Brief tests
# =========================================================================


def test_brief_rejects_uncited_field_and_retries_once():
    case = load_case("CVE-2023-32681")
    source_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    sources = (
        Source(
            url=source_url,
            title="NVD Advisory",
            snippet="advisory text",
            retrieved_at="2026-10-15T00:00:00Z",
        ),
    )
    target_text = "def dummy(): pass\n"

    # Attempt 1: "trigger" citation is missing / empty
    bad_brief = {
        "cwe": "CWE-200",
        "affected_function": "rebuild_proxies",
        "trigger": "redirect with proxy credentials",
        "expected_behaviour": "strip proxy credentials on redirect",
        "citations": {
            "cwe": source_url,
            "affected_function": source_url,
            "trigger": "",  # missing citation
            "expected_behaviour": source_url,
        },
    }
    # Attempt 2: valid brief
    good_brief = {
        "cwe": "CWE-200",
        "affected_function": "rebuild_proxies",
        "trigger": "redirect with proxy credentials",
        "expected_behaviour": "strip proxy credentials on redirect",
        "citations": {
            "cwe": source_url,
            "affected_function": source_url,
            "trigger": source_url,
            "expected_behaviour": source_url,
        },
    }

    client = FakeNemotron([
        _nemotron_response(json.dumps(bad_brief)),
        _nemotron_response(json.dumps(good_brief)),
    ])

    result = brief_stage.run(case, sources, target_text, client)
    assert len(client.calls) == 2
    assert result.cwe == "CWE-200"
    assert result.citations["trigger"] == source_url
    # Ensure attempt 2 had the error feedback
    assert "rejected" in client.calls[1]["messages"][-1]["content"]


def test_brief_rejects_foreign_url_and_retries_once():
    case = load_case("CVE-2023-32681")
    source_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    sources = (
        Source(
            url=source_url,
            title="NVD Advisory",
            snippet="advisory text",
            retrieved_at="2026-10-15T00:00:00Z",
        ),
    )
    target_text = "def dummy(): pass\n"

    # Attempt 1: citation URL not in sources
    foreign_brief = {
        "cwe": "CWE-200",
        "affected_function": "rebuild_proxies",
        "trigger": "redirect with proxy credentials",
        "expected_behaviour": "strip proxy credentials on redirect",
        "citations": {
            "cwe": source_url,
            "affected_function": "https://untrusted-foreign-site.com/vuln",
            "trigger": source_url,
            "expected_behaviour": source_url,
        },
    }
    # Attempt 2: valid brief
    good_brief = {
        "cwe": "CWE-200",
        "affected_function": "rebuild_proxies",
        "trigger": "redirect with proxy credentials",
        "expected_behaviour": "strip proxy credentials on redirect",
        "citations": {
            "cwe": source_url,
            "affected_function": source_url,
            "trigger": source_url,
            "expected_behaviour": source_url,
        },
    }

    client = FakeNemotron([
        _nemotron_response(json.dumps(foreign_brief)),
        _nemotron_response(json.dumps(good_brief)),
    ])

    result = brief_stage.run(case, sources, target_text, client)
    assert len(client.calls) == 2
    assert result.affected_function == "rebuild_proxies"


def test_brief_fails_after_two_invalid_attempts():
    case = load_case("CVE-2023-32681")
    source_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    sources = (
        Source(
            url=source_url,
            title="NVD Advisory",
            snippet="advisory text",
            retrieved_at="2026-10-15T00:00:00Z",
        ),
    )
    target_text = "def dummy(): pass\n"

    bad_brief = {
        "cwe": "CWE-200",
        "affected_function": "rebuild_proxies",
        "trigger": "redirect",
        "expected_behaviour": "strip credentials",
        "citations": {
            "cwe": "https://foreign.org",
            "affected_function": "https://foreign.org",
            "trigger": "https://foreign.org",
            "expected_behaviour": "https://foreign.org",
        },
    }

    client = FakeNemotron([
        _nemotron_response(json.dumps(bad_brief)),
        _nemotron_response(json.dumps(bad_brief)),
    ])

    with pytest.raises(StageFailed) as exc_info:
        brief_stage.run(case, sources, target_text, client)

    assert exc_info.value.stage == "brief"
    assert "not in source URLs" in exc_info.value.reason
    assert len(client.calls) == 2


# =========================================================================
# Stage 3: Repro tests
# =========================================================================


def test_repro_rejects_import_error_test_and_accepts_reference():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
        citations={"cwe": case.advisory_urls[0]},
    )

    import_error_test = (
        "```python\n"
        "import non_existent_bogus_package_12345\n\n"
        "def test_cve():\n"
        "    assert False\n"
        "```"
    )
    good_test = f"```python\n{ref_test}\n```"

    client = FakeNemotron([
        _nemotron_response(import_error_test),
        _nemotron_response(good_test),
    ])

    code, result = repro_stage.run(case, brief, target_text, client)
    assert len(client.calls) == 2
    assert code == ref_test
    assert result.outcome in {"assertion", "timeout"}
    assert result.error_kind is None


def test_repro_rejects_collection_error_test():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    syntax_error_test = (
        "```python\n"
        "def test_syntax(\n"  # Syntax error -> collection failure
        "```"
    )
    good_test = f"```python\n{ref_test}\n```"

    client = FakeNemotron([
        _nemotron_response(syntax_error_test),
        _nemotron_response(good_test),
    ])

    code, result = repro_stage.run(case, brief, target_text, client)
    assert len(client.calls) == 2
    assert code == ref_test
    assert result.outcome in {"assertion", "timeout"}
    assert result.error_kind is None


def test_repro_accepts_reference_test_on_first_try():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    client = FakeNemotron([
        _nemotron_response(f"```python\n{ref_test}\n```"),
    ])

    code, result = repro_stage.run(case, brief, target_text, client)
    assert len(client.calls) == 1
    assert code == ref_test
    assert result.outcome in {"assertion", "timeout"}
    assert result.error_kind is None


# =========================================================================
# Stage 4: Patch tests
# =========================================================================


def test_patch_rejects_diff_touching_another_path():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    foreign_diff = (
        "```diff\n"
        "--- a/requests/other.py\n"
        "+++ b/requests/other.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-a\n"
        "+b\n"
        "```"
    )
    good_diff = f"```diff\n{ref_patch}\n```"

    client = FakeNemotron([
        _nemotron_response(foreign_diff),
        _nemotron_response(good_diff),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 2
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None


def test_patch_rejects_diff_that_leaves_repro_red():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    # A no-op whitespace/comment change to the target file leaves repro test failing
    noop_diff = (
        "```diff\n"
        "--- a/requests/sessions.py\n"
        "+++ b/requests/sessions.py\n"
        "@@ -1,3 +1,4 @@\n"
        "+# Harmless comment\n"
        ' """\n'
        " requests.sessions\n"
        " ~~~~~~~~~~~~~~~~~\n"
        "```"
    )
    good_diff = f"```diff\n{ref_patch}\n```"

    client = FakeNemotron([
        _nemotron_response(noop_diff),
        _nemotron_response(good_diff),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 2
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None


def test_patch_rejects_diff_that_breaks_regression_tests():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    # Patch that passes repro by completely disabling proxy auth, but breaks regression test
    breaking_diff = (
        "```diff\n"
        "--- a/requests/sessions.py\n"
        "+++ b/requests/sessions.py\n"
        "@@ -326,7 +326,7 @@ class SessionRedirectMixin:\n"
        "         except KeyError:\n"
        "             username, password = None, None\n"
        " \n"
        "-        if username and password:\n"
        "+        if False and username and password:\n"
        '             headers["Proxy-Authorization"] = _basic_auth_str(username, password)\n'
        " \n"
        "         return new_proxies\n"
        "```"
    )
    good_diff = f"```diff\n{ref_patch}\n```"

    client = FakeNemotron([
        _nemotron_response(breaking_diff),
        _nemotron_response(good_diff),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 2
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None


def test_patch_accepts_reference_fix():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    client = FakeNemotron([
        _nemotron_response(f"```diff\n{ref_patch}\n```"),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 1
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None


def test_repro_extract_python_fence_variants():
    code_py = "```py\ndef test_py(): pass\n```"
    assert repro_stage._extract_python(code_py) == "def test_py(): pass"

    code_bare = "```\ndef test_bare(): pass\n```"
    assert repro_stage._extract_python(code_bare) == "def test_bare(): pass"

    mixed = "```\nsome non python\n```\n```python\ndef test_preferred(): pass\n```"
    assert repro_stage._extract_python(mixed) == "def test_preferred(): pass"

    first_wins = "```py\ndef first(): pass\n```\n```python\ndef second(): pass\n```"
    assert repro_stage._extract_python(first_wins) == "def first(): pass"


def test_repro_feedback_when_test_passes():
    case = load_case("CVE-2023-32681")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-200",
        affected_function="rebuild_proxies",
        trigger="trigger",
        expected_behaviour="expected",
    )

    passing_test = "```python\ndef test_always_pass():\n    assert True\n```"
    good_test = f"```python\n{ref_test}\n```"

    client = FakeNemotron([
        _nemotron_response(passing_test),
        _nemotron_response(good_test),
    ])

    code, result = repro_stage.run(case, brief, target_text, client)
    assert len(client.calls) == 2
    feedback_msg = client.calls[1]["messages"][-1]["content"]
    assert "PASSED on the vulnerable version" in feedback_msg


def test_patch_search_replace_happy_path():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    search_replace_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )

    client = FakeNemotron([
        _nemotron_response(search_replace_patch),
    ])

    from patchbay import diffutil

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 1
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None
    patched = diffutil.apply(target_text, diff)
    assert 'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'' in patched


def test_patch_search_replace_search_not_found():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    bad_search_patch = (
        '<<<<<<< SEARCH\n'
        'line_one_does_not_exist_in_the_file\n'
        'line_two_does_not_exist\n'
        'line_three_does_not_exist\n'
        'line_four_should_not_be_quoted\n'
        '=======\n'
        'replacement\n'
        '>>>>>>> REPLACE\n'
    )
    good_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )

    client = FakeNemotron([
        _nemotron_response(bad_search_patch),
        _nemotron_response(good_patch),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 2
    assert gate_res is None
    feedback_msg = client.calls[1]["messages"][-1]["content"]
    assert "SEARCH text not found" in feedback_msg
    assert "line_one_does_not_exist_in_the_file" in feedback_msg
    assert "line_two_does_not_exist" in feedback_msg
    assert "line_three_does_not_exist" in feedback_msg
    assert "line_four_should_not_be_quoted" not in feedback_msg


def test_patch_search_replace_ambiguous():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    ambiguous_patch = (
        '<<<<<<< SEARCH\n'
        '    pass\n'
        '=======\n'
        '    pass # replacement\n'
        '>>>>>>> REPLACE\n'
    )
    good_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )

    client = FakeNemotron([
        _nemotron_response(ambiguous_patch),
        _nemotron_response(good_patch),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 2
    assert gate_res is None
    feedback_msg = client.calls[1]["messages"][-1]["content"]
    assert "matches" in feedback_msg and "must match exactly once" in feedback_msg


def test_patch_search_replace_noop_rejection():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    noop_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '>>>>>>> REPLACE\n'
    )
    good_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )

    client = FakeNemotron([
        _nemotron_response(noop_patch),
        _nemotron_response(good_patch),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 2
    assert gate_res is None
    feedback_msg = client.calls[1]["messages"][-1]["content"]
    assert "patch makes no change" in feedback_msg


def test_patch_diff_fallback_accepted():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    ref_patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    client = FakeNemotron([
        _nemotron_response(f"```diff\n{ref_patch}\n```"),
    ])

    diff, green, regression, gate_res = patch_stage.run(case, brief, ref_test, target_text, client)
    assert len(client.calls) == 1
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None


def test_patch_gate_fails_first_then_passes():
    from patchbay import diffutil
    from patchbay.mutate import GateResult, Mutant

    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    broad_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '_EXTRA_UNUSED_GUARD = 42\n'
        '>>>>>>> REPLACE\n'
    )
    narrow_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )

    # Find the line number of _EXTRA_UNUSED_GUARD in the first patched file
    first_patched = target_text.replace(
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'',
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n_EXTRA_UNUSED_GUARD = 42',
        1,
    )
    survivor_line = next(
        idx + 1
        for idx, line in enumerate(first_patched.splitlines())
        if "_EXTRA_UNUSED_GUARD = 42" in line
    )
    survivor = Mutant(
        kind="operator",
        description="change integer 42 by +1",
        line=survivor_line,
        text=first_patched.replace("_EXTRA_UNUSED_GUARD = 42", "_EXTRA_UNUSED_GUARD = 43"),
    )
    failing_gate = GateResult(
        passed=False,
        reversal_killed=1,
        reversal_total=1,
        operator_killed=0,
        operator_total=2,
        score=1 / 3,
        survivors=[survivor],
        results=[],
    )
    passing_gate = GateResult(
        passed=True,
        reversal_killed=1,
        reversal_total=1,
        operator_killed=1,
        operator_total=1,
        score=1.0,
        survivors=[],
        results=[],
    )
    gate_results = [failing_gate, passing_gate]
    on_gate_calls: list[tuple[GateResult, bool]] = []

    client = FakeNemotron([
        _nemotron_response(broad_patch),
        _nemotron_response(narrow_patch),
    ])

    diff, green, regression, gate_res = patch_stage.run(
        case,
        brief,
        ref_test,
        target_text,
        client,
        gate=lambda _d: gate_results.pop(0),
        on_gate=lambda res, retry: on_gate_calls.append((res, retry)),
    )

    assert gate_res == passing_gate
    assert gate_res.passed is True
    assert on_gate_calls == [(failing_gate, True)]
    assert len(client.calls) == 2
    last_user_msg = client.calls[1]["messages"][-1]["content"]
    assert f"- line {survivor_line}: {survivor.description}" in last_user_msg
    assert "_EXTRA_UNUSED_GUARD = 42" in last_user_msg
    assert "33%" in last_user_msg
    assert "No test fails when these changed lines are mutated" in last_user_msg
    assert "_EXTRA_UNUSED_GUARD" not in diffutil.apply(target_text, diff)


def test_patch_gate_always_fails_raises_stage_failed():
    from patchbay.mutate import GateResult, Mutant

    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    good_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )
    failing_gate = GateResult(
        passed=False,
        reversal_killed=0,
        reversal_total=1,
        operator_killed=0,
        operator_total=0,
        score=0.0,
        survivors=[Mutant("hunk_reversal", "revert hunk 1", 1, target_text)],
        results=[],
    )
    on_gate_calls: list[tuple[GateResult, bool]] = []
    client = FakeNemotron([_nemotron_response(good_patch)] * patch_stage.MAX_ATTEMPTS)

    with pytest.raises(StageFailed) as exc_info:
        patch_stage.run(
            case,
            brief,
            ref_test,
            target_text,
            client,
            gate=lambda _d: failing_gate,
            on_gate=lambda res, retry: on_gate_calls.append((res, retry)),
        )

    assert exc_info.value.stage == "patch"
    assert exc_info.value.reason.startswith("Mutation gate failed")
    assert len(client.calls) == patch_stage.MAX_ATTEMPTS
    assert [retry for _, retry in on_gate_calls] == [True, True, True, False]


def test_patch_gate_none_keeps_old_behaviour():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    good_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )
    client = FakeNemotron([_nemotron_response(good_patch)])

    result = patch_stage.run(case, brief, ref_test, target_text, client, gate=None)
    assert isinstance(result, tuple)
    assert len(result) == 4
    diff, green, regression, gate_res = result
    assert green.outcome == "passed"
    assert regression.outcome == "passed"
    assert gate_res is None


def test_patch_gate_error_treated_as_rejected_patch():
    from patchbay.mutate import GateError, GateResult

    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe=case.cwe,
        affected_function=case.summary,
        trigger=case.summary,
        expected_behaviour=case.summary,
    )

    good_patch = (
        '<<<<<<< SEARCH\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"])*"\'\n'
        '=======\n'
        'QUOTED_STR = br\'"(?:\\\\.|[^"\\\\])*"\'\n'
        '>>>>>>> REPLACE\n'
    )
    passing_gate = GateResult(
        passed=True,
        reversal_killed=1,
        reversal_total=1,
        operator_killed=1,
        operator_total=1,
        score=1.0,
        survivors=[],
        results=[],
    )
    calls = 0

    def flaky_gate(_d: str) -> GateResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise GateError("patched test must pass before mutation testing (timeout)")
        return passing_gate

    client = FakeNemotron([
        _nemotron_response(good_patch),
        _nemotron_response(good_patch),
    ])

    diff, green, regression, gate_res = patch_stage.run(
        case, brief, ref_test, target_text, client, gate=flaky_gate
    )
    assert gate_res == passing_gate
    assert len(client.calls) == 2
    assert "patched test must pass before mutation testing (timeout)" in client.calls[1]["messages"][-1]["content"]



def test_repro_rejects_test_that_stays_red_on_upstream_fix():
    # Live Nemotron once asserted the vulnerability itself ("parsing is slow"):
    # red on the vulnerable version, but red on fixed code too, so no patch
    # could ever pass it. Such a test must not count as a reproduction.
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    ref_test = (case.root / "reference" / "test_cve_repro.py").read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-1333",
        affected_function="parse_options_header",
        trigger="trigger",
        expected_behaviour="expected",
    )
    inverted_test = (
        "```python\n"
        "import time\n"
        "from multipart.multipart import parse_options_header\n\n"
        "def test_inverted():\n"
        "    start = time.perf_counter()\n"
        "    parse_options_header(b'a/b; x=\"y\"')\n"
        "    assert time.perf_counter() - start > 0.05\n"
        "```"
    )
    client = FakeNemotron([
        _nemotron_response(inverted_test),
        _nemotron_response(f"```python\n{ref_test}\n```"),
    ])

    code, result = repro_stage.run(case, brief, target_text, client)
    assert code.strip() == ref_test.strip()
    assert len(client.calls) == 2
    feedback_msg = client.calls[1]["messages"][-1]["content"]
    assert "official upstream fix" in feedback_msg


def test_repro_refuses_when_every_test_stays_red_on_upstream_fix():
    case = load_case("CVE-2024-24762")
    _require_site(case)

    target_text = (case.site / case.target).read_text(encoding="utf-8")
    brief = VulnBrief(
        cwe="CWE-1333",
        affected_function="parse_options_header",
        trigger="trigger",
        expected_behaviour="expected",
    )
    always_red = "```python\ndef test_always_red():\n    assert False\n```"
    client = FakeNemotron([_nemotron_response(always_red)] * 3)

    with pytest.raises(StageFailed, match="on fixed version"):
        repro_stage.run(case, brief, target_text, client)
