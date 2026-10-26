from pathlib import Path

import pytest

from patchbay.sandbox import run_pytest


def run(tmp_path, code, *, timeout=10):
    return run_pytest(tmp_path, {"test_candidate.py": code}, "test_candidate.py", timeout=timeout)


def test_passed(tmp_path):
    assert run(tmp_path, "def test_ok():\n    assert True\n").outcome == "passed"


def test_assertion(tmp_path):
    result = run(tmp_path, "def test_bad():\n    assert False\n")
    assert (result.outcome, result.error_kind) == ("assertion", None)


def test_timeout(tmp_path):
    result = run(tmp_path, "def test_loop():\n    while True: pass\n", timeout=2)
    assert result.outcome == "timeout"


def test_import_error(tmp_path):
    result = run(tmp_path, "import module_that_does_not_exist\n")
    assert result.outcome == "error"
    assert result.error_kind in {"ImportError", "ModuleNotFoundError"}


def test_syntax_error(tmp_path):
    result = run(tmp_path, "def broken(:\n    pass\n")
    assert (result.outcome, result.error_kind) == ("error", "SyntaxError")


def test_child_environment_is_stripped(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "parent-secret")
    result = run(tmp_path, "import os\ndef test_no_key():\n    assert 'NEBIUS_API_KEY' not in os.environ\n")
    assert result.outcome == "passed"


def test_candidate_path_cannot_traverse(tmp_path):
    with pytest.raises(ValueError, match="cannot contain"):
        run_pytest(Path(tmp_path), {"../escape.py": "x"}, "test_candidate.py")


def test_did_not_raise_is_an_assertion_not_an_error(tmp_path):
    # A repro test that expects a fix to raise fails with pytest's "DID NOT RAISE";
    # that is a red-for-the-right-reason result, not a broken test.
    source = "import pytest\ndef test_rejects():\n    with pytest.raises(ValueError):\n        pass\n"
    result = run(tmp_path, source)
    assert result.outcome == "assertion"


def test_assertion_message_mentioning_other_errors_is_still_assertion(tmp_path):
    result = run(tmp_path, "def test_bad():\n    assert False, 'ImportError should not appear'\n")
    assert result.outcome == "assertion"


def test_real_value_error_is_an_error(tmp_path):
    result = run(tmp_path, "def test_boom():\n    raise ValueError('x')\n")
    assert (result.outcome, result.error_kind) == ("error", "ValueError")


def test_src_dir_is_importable(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "target_mod.py").write_text("VALUE = 42\n")
    result = run(tmp_path, "import target_mod\ndef test_value():\n    assert target_mod.VALUE == 42\n")
    assert result.outcome == "passed", result.log
