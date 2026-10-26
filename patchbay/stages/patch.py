"""Stage 4: Patch - prompt Nemotron for a unified diff, validating against repro and regression tests."""

from __future__ import annotations

import difflib
import re
from typing import TYPE_CHECKING, Any, Callable

from patchbay import diffutil
from patchbay.clients.nemotron import text as nemotron_text
from patchbay.mutate import GateError, GateResult
from patchbay.sandbox import RunResult, run_pytest
from patchbay.stages import StageFailed

if TYPE_CHECKING:
    from patchbay.cases import Case
    from patchbay.clients.nemotron import NemotronClient
    from patchbay.evidence import VulnBrief

MAX_ATTEMPTS = 4


def _extract_diff(text: str) -> str | None:
    match = re.search(r"```diff\s*\n(.*?)\n```", text, re.DOTALL)
    if match:
        return match.group(1)
    return None


def _extract_edit_blocks(text: str) -> list[tuple[str, str]]:
    text = text.replace("\r\n", "\n")
    pattern = re.compile(
        r"^[ \t]*<{7}[ \t]*SEARCH[ \t]*\n(.*?)\n[ \t]*={7}[ \t]*\n(.*?)(?:\n)?[ \t]*>{7}[ \t]*REPLACE[ \t]*$",
        re.DOTALL | re.MULTILINE,
    )
    return pattern.findall(text)


def _build_prompt(case: Case, brief: VulnBrief, test_code: str, target_text: str) -> str:
    return f"""You are a security engineer writing a patch for a vulnerability.

Case: {case.id}
Package: {case.package}
CWE: {brief.cwe}
Affected function: {brief.affected_function}
Trigger: {brief.trigger}
Expected behaviour: {brief.expected_behaviour}

Reproduction test:
```python
{test_code}
```

Target file to patch ({case.target}):
```python
{target_text}
```

Provide one or more edit blocks in this exact format inside your reply:
<<<<<<< SEARCH
<exact lines copied from the target file>
=======
<replacement lines>
>>>>>>> REPLACE

Requirements:
1. The SEARCH text must be copied verbatim from the target file and must match exactly once.
2. The patch must fix the vulnerability so that the reproduction test PASSES.
3. The patch must not break existing functionality (existing regression tests must PASS).
"""


def run(
    case: Case,
    brief: VulnBrief,
    test_code: str,
    target_text: str,
    nemotron: NemotronClient,
    *,
    gate: Callable[[str], GateResult] | None = None,
    on_gate: Callable[[GateResult, bool], None] | None = None,
) -> tuple[str, RunResult, RunResult, GateResult | None]:
    """Prompt Nemotron for a patch edit, verify in sandbox, and return (norm_diff, green, regression, gate_result)."""
    prompt = _build_prompt(case, brief, test_code, target_text)
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

    last_reason = "unknown"

    for attempt in range(MAX_ATTEMPTS):
        response = nemotron.chat(messages)
        raw = nemotron_text(response)
        edit_blocks = _extract_edit_blocks(raw)

        diff_text: str | None = None
        feedback: str | None = None

        if edit_blocks:
            current_text = target_text
            for search, replace in edit_blocks:
                count = current_text.count(search)
                if count == 0:
                    lines = search.splitlines()[:3]
                    offending = "\n".join(lines) if lines else "<empty>"
                    last_reason = f"SEARCH text not found in target file:\n{offending}"
                    feedback = (
                        f"Patch rejected: SEARCH text not found in {case.target}.\n"
                        f"Offending SEARCH text (first 3 lines):\n{offending}\n"
                        "Ensure the SEARCH block is copied verbatim from the target file."
                    )
                    break
                elif count > 1:
                    lines = search.splitlines()[:3]
                    offending = "\n".join(lines) if lines else "<empty>"
                    last_reason = f"SEARCH text occurs {count} times (must be unique):\n{offending}"
                    feedback = (
                        f"Patch rejected: SEARCH text matches {count} times in {case.target} (must match exactly once).\n"
                        f"Offending SEARCH text (first 3 lines):\n{offending}\n"
                        "Include more surrounding context in the SEARCH block to make it unique."
                    )
                    break
                current_text = current_text.replace(search, replace, 1)

            if feedback is None:
                if current_text == target_text:
                    last_reason = "patch makes no change"
                    feedback = "Patch rejected: patch makes no change."
                else:
                    diff_lines = list(
                        difflib.unified_diff(
                            target_text.splitlines(keepends=True),
                            current_text.splitlines(keepends=True),
                            fromfile=f"a/{case.target}",
                            tofile=f"b/{case.target}",
                        )
                    )
                    diff_text = "".join(diff_lines)
        else:
            diff_block = _extract_diff(raw)
            if diff_block is not None:
                touched = diffutil.touched_paths(diff_block)
                if touched != [case.target]:
                    last_reason = f"Diff touched {touched!r}, but must touch only [{case.target!r}]"
                    feedback = (
                        f"Patch rejected: {last_reason}. "
                        f"Ensure diff headers only reference --- a/{case.target} and +++ b/{case.target}."
                    )
                else:
                    diff_text = diff_block
            else:
                last_reason = "No edit blocks or ```diff ... ``` block found in response"
                feedback = (
                    f"{last_reason}. Please provide the patch using "
                    f"<<<<<<< SEARCH ... ======= ... >>>>>>> REPLACE blocks."
                )

        if diff_text is not None:
            try:
                norm_diff = diffutil.normalize(target_text, diff_text)
                patched = diffutil.apply(target_text, norm_diff)
            except diffutil.PatchError as exc:
                last_reason = f"PatchError applying diff: {exc}"
                feedback = f"Patch rejected: {last_reason}."
            else:
                green = run_pytest(
                    case.root,
                    {f"site/{case.target}": patched, "test_cve_repro.py": test_code},
                    "test_cve_repro.py",
                    case.repro_timeout,
                )
                if green.outcome != "passed":
                    last_reason = f"Repro test did not pass with patch (outcome={green.outcome}, error_kind={green.error_kind})"
                    feedback = (
                        f"Patch rejected: {last_reason}.\n"
                        f"Last 2000 chars of repro test log:\n{green.log[-2000:]}\n"
                        "Please fix the patch so the repro test passes."
                    )
                else:
                    regression = run_pytest(
                        case.root,
                        {f"site/{case.target}": patched},
                        "tests/test_regression.py",
                        case.repro_timeout,
                    )
                    if regression.outcome != "passed":
                        last_reason = f"Regression tests broke with patch (outcome={regression.outcome}, error_kind={regression.error_kind})"
                        feedback = (
                            f"Patch rejected: {last_reason}.\n"
                            f"Last 2000 chars of regression log:\n{regression.log[-2000:]}\n"
                            "Please ensure existing functionality is preserved."
                        )
                    elif gate is None:
                        return norm_diff, green, regression, None
                    else:
                        try:
                            gate_result = gate(norm_diff)
                        except GateError as exc:
                            last_reason = str(exc)
                            feedback = str(exc)
                        else:
                            if gate_result.passed:
                                return norm_diff, green, regression, gate_result
                            patched_lines = patched.splitlines()
                            survivor_lines: list[str] = []
                            for mutant in gate_result.survivors:
                                src_line = (
                                    patched_lines[mutant.line - 1].strip()
                                    if 1 <= mutant.line <= len(patched_lines)
                                    else ""
                                )
                                survivor_lines.append(
                                    f"- line {mutant.line}: {mutant.description} ({src_line})"
                                )
                            survivors_block = "\n".join(survivor_lines)
                            last_reason = f"Mutation gate failed with score {gate_result.score:.0%}"
                            feedback = (
                                f"Patch rejected: {last_reason}.\n"
                                f"Surviving mutants:\n{survivors_block}\n"
                                "No test fails when these changed lines are mutated, so the reproduction test does not check\n"
                                "them. Remove these changes or narrow the patch to exactly what the reproduction test verifies.\n"
                                "Keep the patch minimal. The test itself cannot be changed in this stage."
                            )
                            if on_gate is not None:
                                on_gate(gate_result, attempt < MAX_ATTEMPTS - 1)

        if attempt < MAX_ATTEMPTS - 1:
            assert feedback is not None
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": feedback})
        else:
            if last_reason.startswith("Mutation gate failed with score"):
                raise StageFailed("patch", last_reason)
            raise StageFailed("patch", f"Patch stage failed after {MAX_ATTEMPTS} attempts: {last_reason}")

    raise StageFailed("patch", "Patch stage failed")

