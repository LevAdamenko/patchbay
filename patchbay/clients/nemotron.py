"""OpenAI-compatible Nemotron client with fixture replay."""

from __future__ import annotations

from typing import Any

import httpx

from patchbay.clients import replay
from patchbay.config import Settings


class MissingKey(RuntimeError):
    """Raised before a live request when its provider key is not configured."""


class NemotronClient:
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
        if not self.settings.live:
            return replay.load(self._fixture_dir, "nemotron", fixture_request)
        if not self.settings.nebius_api_key:
            raise MissingKey("NEBIUS_API_KEY is required when LIVE=1")

        url = f"{self.settings.nebius_base_url.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self.settings.nebius_api_key}"}
        models = [self.settings.nemotron_model, self.settings.nemotron_fallback_model]
        last_error: Exception | None = None
        for attempt, model in enumerate(models):
            body: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": self.settings.nemotron_max_tokens,
            }
            if tools is not None:
                body["tools"] = tools
            if response_format is not None:
                body["response_format"] = response_format
            try:
                with httpx.Client(timeout=120.0, transport=self.transport) as client:
                    response = client.post(url, headers=headers, json=body)
                    response.raise_for_status()
                result = response.json()
                if _ran_out_reasoning(result):
                    # Reasoning ate the whole max_tokens budget and left no
                    # answer; ask once more with thinking off rather than
                    # burning a stage attempt on an empty reply.
                    body["chat_template_kwargs"] = {"enable_thinking": False}
                    with httpx.Client(timeout=120.0, transport=self.transport) as client:
                        response = client.post(url, headers=headers, json=body)
                        response.raise_for_status()
                    result = response.json()
                if self.record:
                    replay.save(self._fixture_dir, "nemotron", fixture_request, result)
                return result
            except httpx.TimeoutException as exc:
                last_error = exc
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404 and exc.response.status_code < 500:
                    raise
                last_error = exc
            if attempt == len(models) - 1:
                assert last_error is not None
                raise last_error
        raise AssertionError("unreachable")


def _ran_out_reasoning(response: dict[str, Any]) -> bool:
    choice = (response.get("choices") or [{}])[0]
    return choice.get("finish_reason") == "length" and not text(response).strip()


def text(response: dict[str, Any]) -> str:
    """Return the first assistant message's plain text content."""
    content = response["choices"][0]["message"].get("content") or ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return str(content)
