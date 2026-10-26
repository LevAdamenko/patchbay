"""Stage 1: Research - query Tavily for advisories and commit references."""

from __future__ import annotations

from typing import TYPE_CHECKING

from patchbay.evidence import Source
from patchbay.stages import StageFailed

if TYPE_CHECKING:
    from patchbay.cases import Case
    from patchbay.clients.tavily import TavilyClient

DEFAULT_RETRIEVED_AT = "2026-10-15T00:00:00Z"


def run(
    case: Case,
    tavily: TavilyClient,
    *,
    retrieved_at: str = DEFAULT_RETRIEVED_AT,
) -> tuple[Source, ...]:
    """Execute two targeted Tavily queries and return deduplicated Source records."""
    queries: list[tuple[str, list[str]]] = [
        (
            f"{case.id} {case.package} advisory",
            ["github.com", "nvd.nist.gov", "osv.dev", "security.snyk.io"],
        ),
        (
            f"{case.package} {case.fixed_version} fix {case.id} commit",
            ["github.com"],
        ),
    ]

    seen_urls: set[str] = set()
    sources: list[Source] = []

    for query, domains in queries:
        try:
            results = tavily.search(query, include_domains=domains)
        except Exception as exc:
            raise StageFailed("research", f"Tavily search failed for query {query!r}: {exc}") from exc

        for item in results:
            url = item.get("url")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            ts = item.get("retrieved_at") or retrieved_at
            sources.append(
                Source(
                    url=url,
                    title=item.get("title", ""),
                    snippet=item.get("snippet") or item.get("content", ""),
                    retrieved_at=ts,
                )
            )

    if not sources:
        raise StageFailed("research", f"Zero sources found for case {case.id}")

    return tuple(sources)
