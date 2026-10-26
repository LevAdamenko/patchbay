"""Tavily search client with fixture replay."""

from __future__ import annotations

from typing import Any

import httpx

from patchbay.clients import replay
from patchbay.clients.nemotron import MissingKey
from patchbay.config import Settings


class TavilyClient:
    def __init__(
        self,
        settings: Settings,
        namespace: str,
        *,
        record: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.namespace = namespace
        self.record = record
        self.transport = transport

    @property
    def _fixture_dir(self):
        return self.settings.fixtures_dir / self.namespace

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
        if not self.settings.live:
            response = replay.load(self._fixture_dir, "tavily", request)
        else:
            if not self.settings.tavily_api_key:
                raise MissingKey("TAVILY_API_KEY is required when LIVE=1")
            with httpx.Client(timeout=120.0, transport=self.transport) as client:
                response = client.post(
                    "https://api.tavily.com/search",
                    headers={"Authorization": f"Bearer {self.settings.tavily_api_key}"},
                    json=request,
                )
                response.raise_for_status()
                response = response.json()
            if self.record:
                replay.save(self._fixture_dir, "tavily", request, response)
        return [
            {"url": item["url"], "title": item["title"], "content": item["content"]}
            for item in response.get("results", [])
        ]
