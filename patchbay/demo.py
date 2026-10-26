"""PatchBay demo CLI runner."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from patchbay import pipeline
from patchbay.cases import list_cases, load_case
from patchbay.config import Settings
from patchbay.pipeline import PipelineRefused


def synthetic_cases(fixtures_dir: Path, case_ids: list[str]) -> list[str]:
    """Cases whose fixtures are missing or include any synthetic (hand-built) response."""
    flagged = []
    for case_id in case_ids:
        json_files = sorted((fixtures_dir / case_id).glob("*.json"))
        try:
            synthetic = not json_files or any(
                json.loads(path.read_text(encoding="utf-8")).get("synthetic")
                for path in json_files
            )
        except (OSError, ValueError):
            synthetic = True
        if synthetic:
            flagged.append(case_id)
    return flagged


def replay_banner(fixtures_dir: Path, case_ids: list[str]) -> str:
    """One honest line on where offline replay data comes from."""
    flagged = synthetic_cases(fixtures_dir, case_ids)
    if not flagged:
        return "offline replay of recorded live Nemotron and Tavily responses"
    if len(flagged) == len(case_ids):
        return "offline replay of synthetic fixtures"
    return (
        "offline replay of recorded live Nemotron and Tavily responses; "
        f"synthetic fixtures for {', '.join(flagged)}"
    )


def on_event(event: dict[str, Any]) -> None:
    """Print one line per pipeline event."""
    print(f"[{event['stage']}] {event['status']}: {event['detail']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PatchBay demo runner")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Force LIVE=0 offline replay mode",
    )
    parser.add_argument(
        "--case",
        help="Optional case ID to run (e.g. CVE-2023-32681)",
    )
    args = parser.parse_args(argv)

    if args.offline:
        os.environ["LIVE"] = "0"

    settings = Settings()
    if args.offline:
        settings.live = False

    if args.case:
        cases = [load_case(args.case)]
    else:
        cases = list_cases()

    case_ids = [c.id for c in cases]
    if args.offline or not settings.live:
        print(replay_banner(settings.fixtures_dir, case_ids))

    reports: list[str] = []
    try:
        for case in cases:
            report_md = pipeline.run(case, settings=settings, on_event=on_event)
            reports.append(report_md)
    except PipelineRefused as exc:
        print(exc)
        return 1

    for report_md in reports:
        print(report_md)

    if len(reports) != len(cases):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
