"""A small subprocess boundary for model-generated pytest inputs."""

from __future__ import annotations

import hashlib
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


MAX_LOG_CHARS = 20_000


@dataclass(frozen=True, slots=True)
class RunResult:
    outcome: str
    error_kind: str | None
    log: str
    log_sha256: str
    duration: float


def _safe_relative_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"files path must be relative and cannot contain '..': {name!r}")
    return path


def _preexec(timeout: float):
    """Create Linux-only resource limits for the child process."""
    if platform.system() != "Linux":
        return None

    def set_limits() -> None:
        import resource

        cpu = max(1, math.ceil(timeout))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_AS, (1_024 * 1024 * 1024, 1_024 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))

    return set_limits


_EXCEPTION_RE = re.compile(r"\s*([A-Za-z_][\w.]*)\s*(?::|$)")
_TRACEBACK_E_RE = re.compile(r"^E\s+([A-Za-z_][\w.]*(?:Error|Exception|Failed))\b", re.MULTILINE)
# pytest reports a failed expectation (`pytest.raises` that did not raise,
# `pytest.fail`) as `Failed`; for a repro test that is the same as an assert.
_ASSERTION_KINDS = {"AssertionError", "Failed"}


def _exception_name(node: ET.Element) -> str | None:
    """Name of the exception that ended the test, read from the junit node.

    Only the leading `Name:` of the message counts, so an assertion whose
    message merely mentions another exception is still an assertion.
    """
    message = node.attrib.get("message", "")
    if message.startswith("assert "):  # bare `assert` rewritten by pytest
        return "AssertionError"
    match = _EXCEPTION_RE.match(message)
    if match:
        return match.group(1).rsplit(".", 1)[-1]
    match = _TRACEBACK_E_RE.search(node.text or "")
    if match:
        return match.group(1).rsplit(".", 1)[-1]
    candidate = node.attrib.get("type", "")
    return candidate.rsplit(".", 1)[-1] if candidate else None


def _classify_junit(path: Path) -> tuple[str, str | None]:
    if not path.is_file():
        return "error", "collection"
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return "error", "collection"
    errors = list(root.iter("error"))
    failures = list(root.iter("failure"))
    if errors:
        return "error", _exception_name(errors[0]) or "collection"
    if failures:
        kind = _exception_name(failures[0])
        if kind in _ASSERTION_KINDS:
            return "assertion", None
        return "error", kind or "collection"
    tests = list(root.iter("testcase"))
    if tests:
        return "passed", None
    return "error", "collection"


def _import_roots(tempdir: Path) -> list[str]:
    """Relative import roots: `site/` (fetched case libraries) and `src/`, else the root."""
    roots = [name for name in ("site", "src") if (tempdir / name).is_dir()]
    return roots or ["."]


def run_pytest(
    workdir_src: Path,
    files: dict[str, str],
    test_path: str,
    timeout: float = 10,
) -> RunResult:
    """Run pytest in an isolated disposable copy of *workdir_src*."""
    for name in files:
        _safe_relative_path(name)
    source = Path(workdir_src)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="patchbay-sandbox-") as temp_name:
        tempdir = Path(temp_name)
        shutil.copytree(
            source,
            tempdir,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
        )
        for name, content in files.items():
            target = tempdir / _safe_relative_path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        junit = tempdir / "junit.xml"
        command = [
            sys.executable,
            "-I",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit}",
            # `-I` ignores PYTHONPATH, so the import roots go through pytest itself.
            "-o",
            f"pythonpath={' '.join(_import_roots(tempdir))}",
            test_path,
        ]
        pythonpath = tempdir / "src" if (tempdir / "src").is_dir() else tempdir
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tempdir),
            "PYTHONPATH": str(pythonpath),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        timed_out = False
        try:
            process = subprocess.Popen(
                command,
                cwd=tempdir,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                preexec_fn=_preexec(timeout),
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        except OSError as exc:
            stdout, stderr = "", f"sandbox failed to start: {exc}\n"

        log = (stdout + stderr)[:MAX_LOG_CHARS]
        duration = time.monotonic() - started
        if timed_out:
            outcome, error_kind = "timeout", None
        else:
            outcome, error_kind = _classify_junit(junit)
        return RunResult(
            outcome=outcome,
            error_kind=error_kind,
            log=log,
            log_sha256=hashlib.sha256(log.encode("utf-8")).hexdigest(),
            duration=duration,
        )
