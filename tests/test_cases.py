from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from patchbay.cases import list_cases, load_case
from patchbay.sandbox import run_pytest


CASE_IDS = ("CVE-2023-32681", "CVE-2024-22195", "CVE-2024-24762")


def _require_site(case) -> None:
    if not (case.site / case.target).is_file():
        pytest.skip(f"{case.id} site/ is not fetched; run: python scripts/fetch_cases.py")


def _copy_case(case, tmp_path: Path, name: str) -> Path:
    copied = tmp_path / name
    shutil.copytree(case.root, copied, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    return copied


def _apply_reference_patch(case, destination: Path) -> None:
    result = subprocess.run(
        ["patch", "-p1", "--input", str(case.root / "reference" / "fix.patch")],
        cwd=destination / "site",
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _run(case, root: Path, relative_test: str):
    content = (case.root / relative_test).read_text(encoding="utf-8")
    return run_pytest(root, {relative_test: content}, relative_test, timeout=case.repro_timeout)


def test_catalog_has_the_three_curated_cases():
    cases = list_cases()
    assert tuple(case.id for case in cases) == CASE_IDS
    for case in cases:
        assert load_case(case.id) == case
        assert case.attribution
        assert case.advisory_urls
        for wheel in case.wheels:
            assert len(wheel.sha256) == 64
            assert all(character in "0123456789abcdef" for character in wheel.sha256)


def test_extracted_optional_native_dependencies_have_pure_python_fallbacks():
    jinja_case = load_case("CVE-2024-22195")
    requests_case = load_case("CVE-2023-32681")
    _require_site(jinja_case)
    _require_site(requests_case)
    assert not list(jinja_case.site.rglob("*.so"))
    assert not list(jinja_case.site.rglob("*.pyd"))
    assert not list(requests_case.site.rglob("*.so"))
    assert not list(requests_case.site.rglob("*.pyd"))

    markupsafe = run_pytest(
        jinja_case.root,
        {"test_fallback.py": "import markupsafe\n\ndef test_escape():\n    assert str(markupsafe.escape('<&')) == '&lt;&amp;'\n"},
        "test_fallback.py",
    )
    charset = run_pytest(
        requests_case.root,
        {"test_fallback.py": "import charset_normalizer\n\ndef test_detect():\n    assert str(charset_normalizer.from_bytes(b'plain').best()) == 'plain'\n"},
        "test_fallback.py",
    )
    assert markupsafe.outcome == charset.outcome == "passed"


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_reference_patch_proves_red_to_green_and_preserves_regressions(case_id, tmp_path):
    case = load_case(case_id)
    _require_site(case)
    assert (case.site / case.target).is_file()

    vulnerable = _copy_case(case, tmp_path, "vulnerable")
    red = _run(case, vulnerable, "reference/test_cve_repro.py")
    assert red.outcome in {"assertion", "timeout"}, red.log
    assert red.error_kind is None
    assert _run(case, vulnerable, "tests/test_regression.py").outcome == "passed"

    patched = _copy_case(case, tmp_path, "patched")
    _apply_reference_patch(case, patched)
    green = _run(case, patched, "reference/test_cve_repro.py")
    assert green.outcome == "passed", green.log
    assert _run(case, patched, "tests/test_regression.py").outcome == "passed"


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_reference_patch_touches_only_declared_target(case_id):
    case = load_case(case_id)
    patch = (case.root / "reference" / "fix.patch").read_text(encoding="utf-8")
    changed = [
            line.split("/", 1)[1]
        for line in patch.splitlines()
        if line.startswith(("--- a/", "+++ b/"))
    ]
    assert changed == [case.target, case.target]
    assert hashlib.sha256(patch.encode("utf-8")).hexdigest()
