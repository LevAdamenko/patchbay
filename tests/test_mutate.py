from pathlib import Path

import pytest

from patchbay.mutate import GateError, gate_passes, generate_mutants, run_gate


ORIGINAL = """def clamp_len(s, limit):
    return s[:limit]
"""
DIFF = """--- a/site/toylib/guard.py
+++ b/site/toylib/guard.py
@@ -1,2 +1,6 @@
 def clamp_len(s, limit):
+    if not isinstance(limit, int) or limit < 0:
+        raise ValueError(\"bad limit 7 < 8\")  # not a mutation
+    if limit == 0:
+        return 0
     return s[:limit]
"""
STRONG = """import pytest
from toylib.guard import clamp_len

def test_guard_boundary():
    with pytest.raises(ValueError):
        clamp_len('abc', -1)
    assert clamp_len('abc', 0) == 0
    assert clamp_len('abc', 2) == 'ab'
"""
WEAK = """from toylib.guard import clamp_len

def test_non_boundary():
    assert clamp_len('abc', 2) == 'ab'
"""


def _toy(tmp_path: Path) -> Path:
    (tmp_path / "site/toylib").mkdir(parents=True)
    (tmp_path / "site/toylib/__init__.py").write_text("")
    (tmp_path / "site/toylib/guard.py").write_text(ORIGINAL)
    return tmp_path


def test_operator_generation_is_token_aware():
    mutants = generate_mutants(ORIGINAL, DIFF)
    descriptions = [mutant.description for mutant in mutants if mutant.kind == "operator"]
    assert any("comparison <" in description for description in descriptions)
    assert any("drop not" in description for description in descriptions)
    assert any("raise guard" in description for description in descriptions)
    assert any("integer 0" in description for description in descriptions)
    comparison_mutant = next(mutant for mutant in mutants if mutant.description == "flip comparison <")
    assert "bad limit 7 < 8" in comparison_mutant.text
    assert "# not a mutation" in comparison_mutant.text


def test_strong_boundary_test_passes_gate(tmp_path: Path):
    workdir = _toy(tmp_path)
    result = run_gate(workdir, "site/toylib/guard.py", ORIGINAL, DIFF, {"test_guard.py": STRONG}, "test_guard.py", 5)
    assert result.passed
    assert result.reversal_killed == result.reversal_total
    assert result.operator_killed / result.operator_total >= 0.8


def test_weak_test_leaves_survivors_and_gate_fails(tmp_path: Path):
    workdir = _toy(tmp_path)
    result = run_gate(workdir, "site/toylib/guard.py", ORIGINAL, DIFF, {"test_guard.py": WEAK}, "test_guard.py", 5)
    assert not result.passed
    assert result.survivors
    assert any(mutant.kind == "hunk_reversal" for mutant in result.survivors)
    assert result.reversal_killed < result.reversal_total
    assert len(result.survivors) == (
        result.reversal_total + result.operator_total - result.reversal_killed - result.operator_killed
    )


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ((2, 2, 4, 5), True),  # exactly 80 % of operator mutants
        ((2, 2, 3, 4), False),  # 75 %
        ((2, 2, 79, 100), False),  # just under the threshold
        ((1, 2, 5, 5), False),  # one hunk reversal survived
        ((1, 1, 0, 0), True),  # no operator mutants on the patch
        ((0, 1, 0, 0), False),
    ],
)
def test_gate_rule(counts, expected):
    assert gate_passes(*counts) is expected


def test_gate_rejects_a_non_green_patched_case(tmp_path: Path):
    with pytest.raises(GateError):
        run_gate(_toy(tmp_path), "site/toylib/guard.py", ORIGINAL, DIFF, {"test_guard.py": "def test_bad(): assert False\n"}, "test_guard.py", 5)
