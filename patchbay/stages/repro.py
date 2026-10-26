"""Stage 3: Repro - prompt Nemotron to write a reproduction test that fails on unpatched code."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from patchbay import diffutil
from patchbay.sandbox import RunResult, run_pytest
from patchbay.clients.nemotron import text as nemotron_text
from patchbay.stages import StageFailed

if TYPE_CHECKING:
    from patchbay.cases import Case
    from patchbay.clients.nemotron import NemotronClient
    from patchbay.evidence import VulnBrief


def _extract_python(text: str) -> str | None:
    # Prefer a python-tagged block (```python or ```py)
    match = re.search(r"```(?:python|py)[ \t]*\r?\n(.*?)\r?\n```", text, re.DOTALL)
    if match:
        return match.group(1)
    # Bare ``` fence fallback
    bare_match = re.search(r"```[ \t]*\r?\n(.*?)\r?\n```", text, re.DOTALL)
    if bare_match:
        return bare_match.group(1)
    return None


def _upstream_fixed_text(case: Case, target_text: str) -> str:
    """The target file with the upstream fix applied: an oracle for the test, never shown to the model."""
    fix = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    return diffutil.apply(target_text, diffutil.normalize(target_text, fix))


def _build_prompt(case: Case, brief: VulnBrief, target_text: str) -> str:
    return f"""You are a defensive security engineer writing a reproduction unit test for a confirmed vulnerability.

Case: {case.id}
Package: {case.package} {case.vulnerable_version}
CWE: {brief.cwe}
Affected function: {brief.affected_function}
Trigger: {brief.trigger}
Expected behaviour: {brief.expected_behaviour}

Target file ({case.target}):
```python
{target_text}
```

Write a standalone pytest reproduction test in a single file named test_cve_repro.py.
Requirements:
1. The test must reproduce the vulnerability on the unpatched package.
2. The sandbox kills the test after {case.repro_timeout} seconds, and a timeout counts as a successful reproduction for ReDoS / algorithmic-complexity bugs.
3. pytest-timeout is NOT available, so do NOT use @pytest.mark.timeout.
4. The test must assert on the vulnerable behaviour (for leaks/injection: assert the safe behaviour, which fails on the vulnerable version).
5. It MUST fail with an assertion failure (AssertionError) or time out (for ReDoS/infinite loops).
6. It must NOT fail with an ImportError, SyntaxError, NameError, or test collection error.
7. Import the vulnerable function from the package directly.

Provide your test inside a ```python ... ``` block.
"""


def run(
    case: Case,
    brief: VulnBrief,
    target_text: str,
    nemotron: NemotronClient,
) -> tuple[str, RunResult]:
    """Prompt Nemotron for test_cve_repro.py; accept it only if red on unpatched code and green on the upstream fix."""
    prompt = _build_prompt(case, brief, target_text)
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

    fixed_text = _upstream_fixed_text(case, target_text)
    last_outcome = "unknown"
    last_error_kind: str | None = None

    for attempt in range(3):
        response = nemotron.chat(messages)
        raw = nemotron_text(response)
        code = _extract_python(raw)

        if code is None:
            last_outcome = "error"
            last_error_kind = "no_code_block"
            feedback = (
                "The reply contained no code block. Provide ONLY the test file in one ```python ... ``` block, with brief reasoning."
            )
        else:
            result = run_pytest(
                case.root,
                {"test_cve_repro.py": code},
                "test_cve_repro.py",
                case.repro_timeout,
            )
            red = result.outcome in {"assertion", "timeout"} and result.error_kind is None
            fixed: RunResult | None = None
            if red:
                # A test that is red for the wrong reason (e.g. it asserts the
                # vulnerability exists) stays red on fixed code: no patch can
                # ever turn it green, so it is not a reproduction.
                fixed = run_pytest(
                    case.root,
                    {f"site/{case.target}": fixed_text, "test_cve_repro.py": code},
                    "test_cve_repro.py",
                    case.repro_timeout,
                )
                if fixed.outcome == "passed":
                    return code, result

            last_outcome = result.outcome if fixed is None else f"{fixed.outcome} on fixed version"
            last_error_kind = result.error_kind if fixed is None else fixed.error_kind
            if fixed is not None:
                feedback = (
                    "Test rejected: it fails on the vulnerable version, but it ALSO fails "
                    f"(outcome={fixed.outcome}) on the version with the official upstream fix, "
                    "so it does not distinguish vulnerable from fixed code. Assert the SAFE "
                    "behaviour (what a fixed version does), not the vulnerable one; for ReDoS, "
                    "just call the function with the malicious input and let the time limit fail it.\n"
                    f"Last 2000 chars of the log on the fixed version:\n{fixed.log[-2000:]}"
                )
            elif result.outcome == "passed":
                feedback = (
                    f"Test rejected: the test PASSED on the vulnerable version, so it did not reproduce the bug.\n"
                    f"Please re-read the target source, find the exact vulnerable code path, and make the input trigger it "
                    f"(for ReDoS: larger input that defeats the regex, run within the time limit).\n"
                    f"Last 2000 chars of test log:\n{result.log[-2000:]}"
                )
            else:
                feedback = (
                    f"Test rejected: outcome={result.outcome}, error_kind={result.error_kind}.\n"
                    f"Last 2000 chars of test log:\n{result.log[-2000:]}\n"
                    "Please fix the test so it fails only with an assertion or timeout (and no collection or import error)."
                )

        if attempt < 2:
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": feedback})
        else:
            raise StageFailed(
                "repro",
                f"Repro test failed after 3 attempts (outcome={last_outcome}, error_kind={last_error_kind})",
            )

    raise StageFailed("repro", "Repro stage failed")
