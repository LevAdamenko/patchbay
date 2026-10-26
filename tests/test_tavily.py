import json

import httpx

from patchbay.clients import replay
from patchbay.clients.tavily import TavilyClient
from patchbay.config import Settings


def settings(monkeypatch, tmp_path, *, live=False):
    monkeypatch.setenv("PATCHBAY_SECRETS_FILE", str(tmp_path / "missing"))
    monkeypatch.setenv("FIXTURES_DIR", str(tmp_path / "fixtures"))
    monkeypatch.setenv("LIVE", "1" if live else "0")
    monkeypatch.setenv("TAVILY_API_KEY", "tavily-key")
    return Settings()


def test_offline_replay(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path)
    request = {"query": "cve", "include_domains": None, "max_results": 5, "search_depth": "basic"}
    replay.save(config.fixtures_dir / "unit", "tavily", request, {"results": [{"url": "u", "title": "t", "content": "c", "score": 1}]})

    assert TavilyClient(config, "unit").search("cve") == [{"url": "u", "title": "t", "content": "c"}]


def test_live_body_includes_domains(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path, live=True)
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"results": []})

    TavilyClient(config, "unit", transport=httpx.MockTransport(handler)).search(
        "query", include_domains=["github.com"]
    )

    assert seen["body"] == {"query": "query", "include_domains": ["github.com"], "max_results": 5, "search_depth": "basic"}
