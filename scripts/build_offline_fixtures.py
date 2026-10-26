#!/usr/bin/env python3
"""Build synthetic offline fixtures for curated PatchBay cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from patchbay import pipeline
from patchbay.cases import Case, list_cases, load_case
from patchbay.clients import replay
from patchbay.config import Settings


def _save_synthetic_fixture(directory: Path, kind: str, payload: Any, response: Any) -> Path:
    path = replay.save(directory, kind, payload, response)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["synthetic"] = True
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


class RecordingTavilyClient:
    def __init__(self, case: Case, fixtures_dir: Path) -> None:
        self.case = case
        self.fixtures_dir = fixtures_dir / case.id

    def search(
        self,
        query: str,
        include_domains: list[str] | None = None,
        max_results: int = 5,
    ) -> list[dict[str, str]]:
        request = {
            "query": query,
            "include_domains": include_domains,
            "max_results": max_results,
            "search_depth": "basic",
        }
        results = [
            {
                "url": url,
                "title": f"{self.case.id} advisory",
                "content": self.case.summary,
                "retrieved_at": "2026-10-15T00:00:00Z",
            }
            for url in self.case.advisory_urls
        ]
        response = {"results": results}
        _save_synthetic_fixture(self.fixtures_dir, "tavily", request, response)
        return [
            {"url": item["url"], "title": item["title"], "content": item["content"]}
            for item in results
        ]


class RecordingNemotronClient:
    def __init__(self, case: Case, fixtures_dir: Path) -> None:
        self.case = case
        self.fixtures_dir = fixtures_dir / case.id

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        fixture_request = {
            "messages": messages,
            "tools": tools,
            "response_format": response_format,
        }
        user_content = messages[0]["content"] if messages else ""

        if "You are a security vulnerability analyst." in user_content:
            fields = ("cwe", "affected_function", "trigger", "expected_behaviour")
            citations = {
                field: self.case.advisory_urls[i % len(self.case.advisory_urls)]
                for i, field in enumerate(fields)
            }
            brief_dict = {
                "cwe": self.case.cwe,
                "affected_function": self.case.summary,
                "trigger": self.case.summary,
                "expected_behaviour": self.case.summary,
                "citations": citations,
            }
            content = json.dumps(brief_dict, indent=2, sort_keys=True)
        elif "You are a defensive security engineer writing a reproduction unit test" in user_content:
            repro_path = self.case.root / "reference" / "test_cve_repro.py"
            content = "```python\n" + repro_path.read_text(encoding="utf-8") + "\n```"
        elif "You are a security engineer writing a patch for a vulnerability" in user_content:
            patch_path = self.case.root / "reference" / "fix.patch"
            content = "```diff\n" + patch_path.read_text(encoding="utf-8") + "\n```"
        else:
            raise ValueError(f"Unexpected prompt in RecordingNemotronClient: {user_content[:100]}...")

        response = {
            "choices": [
                {
                    "message": {
                        "content": content,
                        "role": "assistant",
                    }
                }
            ]
        }
        _save_synthetic_fixture(self.fixtures_dir, "nemotron", fixture_request, response)
        return response


def build_fixtures_for_case(case: Case, fixtures_dir: Path) -> None:
    case_fixtures_dir = fixtures_dir / case.id
    if case_fixtures_dir.exists():
        for file in case_fixtures_dir.glob("*.json"):
            file.unlink()
    case_fixtures_dir.mkdir(parents=True, exist_ok=True)

    tavily = RecordingTavilyClient(case, fixtures_dir)
    nemotron = RecordingNemotronClient(case, fixtures_dir)
    settings = Settings()
    settings.live = False
    pipeline.run(case, settings=settings, tavily=tavily, nemotron=nemotron)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build synthetic offline fixtures")
    parser.add_argument("--case", nargs="*", help="Optional case IDs to build")
    args = parser.parse_args()

    settings = Settings()
    fixtures_dir = settings.fixtures_dir

    if args.case:
        cases = [load_case(cid) for cid in args.case]
    else:
        cases = list_cases()

    for case in cases:
        print(f"Building synthetic offline fixtures for {case.id}...")
        build_fixtures_for_case(case, fixtures_dir)
        print(f"Done building fixtures for {case.id}.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
