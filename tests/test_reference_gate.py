"""The reference repro test of every curated case must pass the mutation gate."""

from __future__ import annotations

import pytest

from patchbay.cases import list_cases
from patchbay.mutate import run_gate


@pytest.mark.parametrize("case", list_cases(), ids=lambda case: case.id)
def test_reference_repro_test_passes_the_mutation_gate(case):
    if not (case.site / case.target).is_file():
        pytest.skip(f"{case.id} site/ is not fetched; run: python scripts/fetch_cases.py")
    test_path = "reference/test_cve_repro.py"
    result = run_gate(
        case.root,
        f"site/{case.target}",
        (case.site / case.target).read_text(encoding="utf-8"),
        (case.root / "reference" / "fix.patch").read_text(encoding="utf-8"),
        {test_path: (case.root / test_path).read_text(encoding="utf-8")},
        test_path,
        case.repro_timeout,
    )
    assert result.reversal_total >= 1
    assert result.passed, [mutant.description for mutant in result.survivors]
