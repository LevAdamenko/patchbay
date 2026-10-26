import json

import httpx
import pytest

from patchbay.clients import replay
from patchbay.clients.nemotron import MissingKey, NemotronClient, text
from patchbay.config import Settings


def settings(monkeypatch, tmp_path, *, live=False, key="nebius-key"):
    monkeypatch.setenv("PATCHBAY_SECRETS_FILE", str(tmp_path / "missing"))
    monkeypatch.setenv("FIXTURES_DIR", str(tmp_path / "fixtures"))
    monkeypatch.setenv("LIVE", "1" if live else "0")
    if key is None:
        monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NEBIUS_API_KEY", key)
    return Settings()


def test_offline_replay(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path)
    messages = [{"role": "user", "content": "hello"}]
    request = {"messages": messages, "tools": None, "response_format": None}
    replay.save(config.fixtures_dir / "unit", "nemotron", request, {"choices": [{"message": {"content": "hi"}}]})

    response = NemotronClient(config, "unit").chat(messages)

    assert text(response) == "hi"


def test_live_request_uses_url_header_and_model(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path, live=True)
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})

    client = NemotronClient(config, "unit", transport=httpx.MockTransport(handler))
    client.chat([{"role": "user", "content": "hello"}])

    assert seen["url"] == "https://api.tokenfactory.nebius.com/v1/chat/completions"
    assert seen["auth"] == "Bearer nebius-key"
    assert seen["body"]["model"] == config.nemotron_model
    assert seen["body"]["max_tokens"] == config.nemotron_max_tokens


def test_live_request_sends_custom_max_tokens(monkeypatch, tmp_path):
    monkeypatch.setenv("NEMOTRON_MAX_TOKENS", "12345")
    config = settings(monkeypatch, tmp_path, live=True)
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = NemotronClient(config, "unit", transport=httpx.MockTransport(handler))
    client.chat([{"role": "user", "content": "hi"}])
    assert seen["body"]["max_tokens"] == 12345


def test_fixture_hash_unaffected_by_max_tokens(monkeypatch, tmp_path):
    monkeypatch.setenv("NEMOTRON_MAX_TOKENS", "4096")
    config = settings(monkeypatch, tmp_path, live=False)
    messages = [{"role": "user", "content": "hello"}]
    request = {"messages": messages, "tools": None, "response_format": None}
    saved_path = replay.save(
        config.fixtures_dir / "unit",
        "nemotron",
        request,
        {"choices": [{"message": {"content": "hi"}}]},
    )

    # Change max_tokens to a different value, replay should still find the same file
    monkeypatch.setenv("NEMOTRON_MAX_TOKENS", "99999")
    config2 = settings(monkeypatch, tmp_path, live=False)
    response = NemotronClient(config2, "unit").chat(messages)
    assert text(response) == "hi"

    expected_path = config.fixtures_dir / "unit" / f"nemotron-{replay.key('nemotron', request)}.json"
    assert saved_path == expected_path


def test_text_never_returns_reasoning_content():
    response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "the actual patch or repro",
                    "reasoning_content": "internal reasoning that must never be returned",
                }
            }
        ]
    }
    assert text(response) == "the actual patch or repro"


def test_live_retries_fallback_after_503(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path, live=True)
    models = []

    def handler(request):
        models.append(json.loads(request.content)["model"])
        if len(models) == 1:
            return httpx.Response(503, json={"error": "busy"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    response = NemotronClient(config, "unit", transport=httpx.MockTransport(handler)).chat([])

    assert text(response) == "ok"
    assert models == [config.nemotron_model, config.nemotron_fallback_model]


def test_live_requires_key(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path, live=True, key=None)
    with pytest.raises(MissingKey, match="NEBIUS_API_KEY"):
        NemotronClient(config, "unit").chat([])



def test_reasoning_runaway_retries_once_with_thinking_off(monkeypatch, tmp_path):
    # Live: nemotron-3-super spent all 32768 tokens reasoning and returned
    # finish_reason=length with null content.
    config = settings(monkeypatch, tmp_path, live=True)
    bodies = []

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        if "chat_template_kwargs" in body:
            return httpx.Response(200, json={"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": None}, "finish_reason": "length"}]})

    client = NemotronClient(config, "unit", record=True, transport=httpx.MockTransport(handler))
    messages = [{"role": "user", "content": "hello"}]
    assert text(client.chat(messages)) == "answer"
    assert len(bodies) == 2
    assert "chat_template_kwargs" not in bodies[0]
    assert bodies[1]["chat_template_kwargs"] == {"enable_thinking": False}

    config.live = False
    assert text(NemotronClient(config, "unit").chat(messages)) == "answer"


def test_truncated_answer_with_content_is_not_retried(monkeypatch, tmp_path):
    config = settings(monkeypatch, tmp_path, live=True)
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"choices": [{"message": {"content": "partial"}, "finish_reason": "length"}]})

    client = NemotronClient(config, "unit", transport=httpx.MockTransport(handler))
    assert text(client.chat([{"role": "user", "content": "hi"}])) == "partial"
    assert len(calls) == 1
