"""Export a static, self-contained replay of the offline demo for hosting.

Runs the offline pipeline for every case, records each event with its elapsed
time, and writes:

    <out>/index.html          the web demo page in static-replay mode
    <out>/data/<case>.json    {"case_id", "events": [{"t", "event", "data"}]}

The page fetches data/<case>.json and plays the events back in the browser, so
any static host can serve <out>/ with no Python, sandbox, or API keys.

    python scripts/export_static_demo.py [--out site]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from patchbay import pipeline
from patchbay.cases import Case, list_cases
from patchbay.config import Settings
from patchbay.pipeline import PipelineRefused
from patchbay.web import _render_index_html


def record_run(case: Case) -> dict[str, Any]:
    """Run one case offline and return its timed event log."""
    settings = Settings()
    settings.live = False
    events: list[dict[str, Any]] = []
    start = time.monotonic()

    def add(event: str, data: dict[str, Any]) -> None:
        events.append({"t": round(time.monotonic() - start, 3), "event": event, "data": data})

    try:
        report_md = pipeline.run(case, settings=settings, on_event=lambda ev: add("stage", ev))
        add("report", {"case_id": case.id, "markdown": report_md})
    except PipelineRefused as exc:
        add("refused", {"stage": exc.stage, "reason": exc.reason})
    return {"case_id": case.id, "events": events}


def export(out: Path) -> list[dict[str, Any]]:
    data_dir = out / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for case in list_cases():
        run = record_run(case)
        (data_dir / f"{case.id}.json").write_text(
            json.dumps(run, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        runs.append(run)
    (out / "index.html").write_text(_render_index_html(static=True), encoding="utf-8")
    return runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("site"), help="Output directory (default: site)")
    args = parser.parse_args(argv)

    runs = export(args.out)
    failed = [r["case_id"] for r in runs if r["events"][-1]["event"] != "report"]
    for run in runs:
        print(f"{run['case_id']}: {len(run['events'])} events, last={run['events'][-1]['event']}")
    if failed:
        print(f"refused: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"wrote {args.out}/index.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
