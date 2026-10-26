#!/usr/bin/env python3
"""Record live Nemotron and Tavily responses into fixtures/<case_id>/."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

# Add repo root to sys.path like other scripts
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from patchbay import pipeline
from patchbay.cases import Case, list_cases, load_case
from patchbay.clients import replay
from patchbay.clients.nemotron import NemotronClient
from patchbay.clients.tavily import TavilyClient
from patchbay.config import Settings
from patchbay.pipeline import PipelineRefused


class TavilyReuseClient:
    """Wrapper that queries Tavily live at most once per distinct query across attempts."""

    def __init__(
        self,
        staging_dir: Path,
        case_id: str,
        live_client: TavilyClient,
        cache_dir: Path | None = None,
    ) -> None:
        self.fixture_dir = staging_dir / case_id
        self.case_id = case_id
        self.live_client = live_client
        self.cache_dir = (Path(cache_dir) / case_id) if cache_dir is not None else None

    @property
    def settings(self) -> Settings:
        return self.live_client.settings

    @property
    def namespace(self) -> str:
        return self.live_client.namespace

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
        # 1. Look up in DIR/<case_id>/tavily-*.json first
        if self.cache_dir is not None:
            try:
                response = replay.load(self.cache_dir, "tavily", request)
                self.fixture_dir.mkdir(parents=True, exist_ok=True)
                replay.save(self.fixture_dir, "tavily", request, response)
                return [
                    {"url": item["url"], "title": item["title"], "content": item["content"]}
                    for item in response.get("results", [])
                ]
            except (replay.FixtureMissing, FileNotFoundError):
                pass

        # 2. Look up in staging dir
        try:
            response = replay.load(self.fixture_dir, "tavily", request)
            if self.cache_dir is not None:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                replay.save(self.cache_dir, "tavily", request, response)
            return [
                {"url": item["url"], "title": item["title"], "content": item["content"]}
                for item in response.get("results", [])
            ]
        except (replay.FixtureMissing, FileNotFoundError):
            pass

        # 3. Only then call live
        results = self.live_client.search(
            query, include_domains=include_domains, max_results=max_results
        )
        if self.cache_dir is not None:
            try:
                response = replay.load(self.fixture_dir, "tavily", request)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                replay.save(self.cache_dir, "tavily", request, response)
            except Exception:
                pass
        return results


def _on_event(event: dict[str, Any]) -> None:
    print(f"[{event['stage']}] {event['status']}: {event['detail']}")


def _copy_failed_transcripts(
    attempt_files: list[Path],
    dest_dir: Path,
    keys_to_check: list[str],
    forbidden_tokens: list[str],
) -> None:
    if not attempt_files:
        return
    for f in attempt_files:
        content = f.read_text(encoding="utf-8")
        for k in keys_to_check:
            if k in content:
                return  # Skip copy if a key is found
        for token in forbidden_tokens:
            if token in content:
                return  # Skip copy if forbidden token is found
    dest_dir.mkdir(parents=True, exist_ok=True)
    for f in attempt_files:
        shutil.copy2(f, dest_dir / f.name)


def record_case(
    case: Case | str,
    settings: Settings,
    *,
    attempts: int = 3,
    tavily_transport: httpx.BaseTransport | None = None,
    nemotron_transport: httpx.BaseTransport | None = None,
    tavily_cache_dir: Path | None = None,
) -> bool:
    if isinstance(case, str):
        case = load_case(case)

    with tempfile.TemporaryDirectory() as staging_dir_str:
        staging_dir = Path(staging_dir_str)

        staging_settings = Settings()
        staging_settings.live = True
        staging_settings.nebius_api_key = settings.nebius_api_key
        staging_settings.tavily_api_key = settings.tavily_api_key
        staging_settings.nemotron_model = settings.nemotron_model
        staging_settings.nemotron_fallback_model = settings.nemotron_fallback_model
        staging_settings.nebius_base_url = settings.nebius_base_url
        staging_settings.fixtures_dir = staging_dir

        live_tavily = TavilyClient(
            staging_settings,
            namespace=case.id,
            record=True,
            transport=tavily_transport,
        )
        tavily_wrapper = TavilyReuseClient(
            staging_dir, case.id, live_tavily, cache_dir=tavily_cache_dir
        )

        succeeded = False
        staging_case_dir = staging_dir / case.id
        temp_failed_dir = staging_dir / "failed_attempts"
        temp_failed_dir.mkdir(parents=True, exist_ok=True)

        keys_to_check = [k for k in (settings.nebius_api_key, settings.tavily_api_key) if k]
        forbidden_tokens = ["Bearer ", "api_key"]

        def save_failed_transcripts() -> None:
            if tavily_cache_dir is None:
                return
            for attempt_dir in sorted(temp_failed_dir.glob("failed-attempt-*")):
                files = list(attempt_dir.glob("nemotron-*.json"))
                dest_dir = tavily_cache_dir / case.id / attempt_dir.name
                _copy_failed_transcripts(files, dest_dir, keys_to_check, forbidden_tokens)

        for attempt in range(1, attempts + 1):
            if staging_case_dir.exists():
                for nf in staging_case_dir.glob("nemotron-*.json"):
                    nf.unlink()

            nemotron_client = NemotronClient(
                staging_settings,
                namespace=case.id,
                record=True,
                transport=nemotron_transport,
            )

            try:
                pipeline.run(
                    case,
                    settings=staging_settings,
                    tavily=tavily_wrapper,
                    nemotron=nemotron_client,
                    on_event=_on_event,
                )
                succeeded = True
                break
            except PipelineRefused as exc:
                print(f"attempt {attempt}/{attempts} refused at {exc.stage}: {exc.reason}")
            except Exception as exc:
                print(f"attempt {attempt}/{attempts} refused at unknown: {exc}")

            if staging_case_dir.exists():
                attempt_dir = temp_failed_dir / f"failed-attempt-{attempt}"
                attempt_dir.mkdir(parents=True, exist_ok=True)
                for nf in staging_case_dir.glob("nemotron-*.json"):
                    shutil.copy2(nf, attempt_dir / nf.name)

        if not succeeded:
            save_failed_transcripts()
            print(f"KEPT SYNTHETIC {case.id}")
            return False

        staged_files = sorted(staging_case_dir.glob("*.json"))
        if not staged_files:
            save_failed_transcripts()
            print(f"KEPT SYNTHETIC {case.id}")
            return False

        # Scan staged files for secret leak or forbidden strings
        for sf in staged_files:
            content = sf.read_text(encoding="utf-8")
            for k in keys_to_check:
                if k in content:
                    save_failed_transcripts()
                    print(f"KEPT SYNTHETIC {case.id}")
                    return False
            for token in forbidden_tokens:
                if token in content:
                    save_failed_transcripts()
                    print(f"KEPT SYNTHETIC {case.id}")
                    return False

        # Files must NOT contain a "synthetic" field
        for sf in staged_files:
            try:
                doc = json.loads(sf.read_text(encoding="utf-8"))
                if "synthetic" in doc:
                    del doc["synthetic"]
                    sf.write_text(
                        json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8",
                    )
            except Exception:
                pass

        dest_case_dir = settings.fixtures_dir / case.id
        with tempfile.TemporaryDirectory() as backup_tmp_str:
            backup_case_dir = Path(backup_tmp_str) / case.id
            had_existing = dest_case_dir.exists()
            if had_existing:
                shutil.copytree(dest_case_dir, backup_case_dir)

            dest_case_dir.mkdir(parents=True, exist_ok=True)
            for old_json in dest_case_dir.glob("*.json"):
                old_json.unlink()
            for sf in staged_files:
                shutil.copy2(sf, dest_case_dir / sf.name)

            # Offline verification
            verify_settings = Settings()
            verify_settings.live = False
            verify_settings.fixtures_dir = settings.fixtures_dir

            try:
                report_md = pipeline.run(case, settings=verify_settings)
                if not report_md:
                    raise ValueError("Offline pipeline run did not return a report")
            except Exception as exc:
                print(f"Offline replay verification failed for {case.id}: {exc}")
                for cur_json in dest_case_dir.glob("*.json"):
                    cur_json.unlink()
                if had_existing and backup_case_dir.exists():
                    for bkp_file in backup_case_dir.glob("*"):
                        shutil.copy2(bkp_file, dest_case_dir / bkp_file.name)
                else:
                    shutil.rmtree(dest_case_dir, ignore_errors=True)
                attempt_dir = temp_failed_dir / f"failed-attempt-{attempts}"
                attempt_dir.mkdir(parents=True, exist_ok=True)
                for sf in staged_files:
                    if sf.name.startswith("nemotron-"):
                        shutil.copy2(sf, attempt_dir / sf.name)
                save_failed_transcripts()
                print(f"KEPT SYNTHETIC {case.id}")
                return False

    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record live Nemotron and Tavily fixtures")
    parser.add_argument("--case", metavar="CVE-ID", help="Optional case ID to record")
    parser.add_argument(
        "--attempts", type=int, default=3, metavar="N", help="Max attempts per case (default: 3)"
    )
    parser.add_argument(
        "--tavily-cache",
        metavar="DIR",
        type=Path,
        default=Path(".record-cache"),
        help="Directory to cache Tavily responses (default: .record-cache/)",
    )
    args = parser.parse_args(argv)

    settings = Settings()
    if not settings.live or not settings.nebius_api_key or not settings.tavily_api_key:
        print(
            "Refusing to record: Settings().live must be True and both NEBIUS_API_KEY and TAVILY_API_KEY must be set.",
            file=sys.stderr,
        )
        return 2

    if args.case:
        cases = [load_case(args.case)]
    else:
        cases = list_cases()

    results: dict[str, bool] = {}
    for case in cases:
        ok = record_case(
            case,
            settings,
            attempts=args.attempts,
            tavily_cache_dir=args.tavily_cache,
        )
        results[case.id] = ok

    for case_id, ok in results.items():
        if ok:
            print(f"RECORDED {case_id}")
        else:
            print(f"KEPT SYNTHETIC {case_id}")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

