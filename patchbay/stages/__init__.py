"""PatchBay pipeline stages."""

from __future__ import annotations


class StageFailed(RuntimeError):
    """Raised when an individual pipeline stage cannot complete."""

    def __init__(self, stage: str, reason: str) -> None:
        super().__init__(f"Stage '{stage}' failed: {reason}")
        self.stage = stage
        self.reason = reason
