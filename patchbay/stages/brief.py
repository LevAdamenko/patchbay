"""Stage 2: Brief - generate structured VulnBrief with citations from research sources."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from patchbay.evidence import VulnBrief
from patchbay.clients.nemotron import text as nemotron_text
from patchbay.stages import StageFailed

if TYPE_CHECKING:
    from patchbay.cases import Case
    from patchbay.clients.nemotron import NemotronClient
    from patchbay.evidence import Source

_FIELDS = ("cwe", "affected_function", "trigger", "expected_behaviour")


def _extract_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(text[start : end + 1])

    raise ValueError("No valid JSON object found in response")


def _validate_brief(data: Any, source_urls: set[str]) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, "Response is not a JSON object"
    for field in _FIELDS:
        val = data.get(field)
        if val is None or not str(val).strip():
            return False, f"Field '{field}' is empty or missing"
    citations = data.get("citations")
    if not isinstance(citations, dict):
        return False, "Field 'citations' is missing or not an object"
    for field in _FIELDS:
        url = citations.get(field)
        if not url or not str(url).strip():
            return False, f"Citation for '{field}' is empty or missing"
        if url not in source_urls:
            return False, f"Citation URL '{url}' for '{field}' is not in source URLs"
    return True, ""


def _build_prompt(case: Case, sources: tuple[Source, ...], target_text: str) -> str:
    source_items = "\n".join(
        f"- URL: {s.url}\n  Title: {s.title}\n  Snippet: {s.snippet}"
        for s in sources
    )
    return f"""You are a security vulnerability analyst.
Analyze the following vulnerability and target source code, and return a JSON object describing the vulnerability.

Case: {case.id}
Package: {case.package} (vulnerable: {case.vulnerable_version}, fixed: {case.fixed_version})
Summary: {case.summary}
CWE: {case.cwe}

Sources:
{source_items}

Target file ({case.target}):
```python
{target_text}
```

Produce a JSON object with EXACTLY the following keys:
- "cwe": the CWE identifier (e.g. "{case.cwe}")
- "affected_function": name of the vulnerable function or method
- "trigger": description or example of input triggering the vulnerability
- "expected_behaviour": expected safe behaviour
- "citations": an object mapping each of the 4 fields ("cwe", "affected_function", "trigger", "expected_behaviour") to one of the Source URLs listed above.

Every field must be non-empty, and every citation URL must be one of the provided Source URLs.
Output ONLY the JSON object.
"""


def run(
    case: Case,
    sources: tuple[Source, ...],
    target_text: str,
    nemotron: NemotronClient,
) -> VulnBrief:
    """Prompt Nemotron for a VulnBrief, validating required fields and citations."""
    source_urls = {s.url for s in sources}
    prompt = _build_prompt(case, sources, target_text)
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

    for attempt in range(2):
        response = nemotron.chat(messages)
        raw = nemotron_text(response)
        try:
            data = _extract_json(raw)
            valid, reason = _validate_brief(data, source_urls)
        except Exception as exc:
            valid, reason = False, f"Failed to parse JSON: {exc}"

        if valid:
            return VulnBrief(
                cwe=str(data["cwe"]).strip(),
                affected_function=str(data["affected_function"]).strip(),
                trigger=str(data["trigger"]).strip(),
                expected_behaviour=str(data["expected_behaviour"]).strip(),
                citations={f: str(data["citations"][f]).strip() for f in _FIELDS},
            )

        if attempt == 0:
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": (
                    f"The response was rejected: {reason}. "
                    "Please fix the JSON output and ensure all 4 fields "
                    "(cwe, affected_function, trigger, expected_behaviour) are non-empty "
                    "and their citations point to the provided Source URLs."
                ),
            })
        else:
            raise StageFailed("brief", reason)

    raise StageFailed("brief", "Brief stage failed")
