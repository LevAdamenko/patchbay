import subprocess
import sys
from pathlib import Path


def test_probe_runs_offline():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/probe_nemotron.py"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "ready" in result.stdout
