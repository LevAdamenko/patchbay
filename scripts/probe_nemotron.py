"""Make a small Nemotron health probe, replaying the committed fixture by default."""

from __future__ import annotations

import sys
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from patchbay.clients.nemotron import NemotronClient, text
from patchbay.config import Settings


def main() -> None:
    record = "--record" in sys.argv[1:]
    settings = Settings()
    client = NemotronClient(settings, "probe", record=record)
    started = time.monotonic()
    response = client.chat([{"role": "user", "content": "Reply with the single word: ready"}])
    latency = time.monotonic() - started
    print(f"model: {response.get('model', settings.nemotron_model)}")
    print(f"latency: {latency:.3f}s")
    print(f"reply: {text(response)}")


if __name__ == "__main__":
    main()
