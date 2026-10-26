"""Immutable, hashable evidence records for PatchBay reports."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field

from .mutate import GateResult
from .sandbox import RunResult


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Source:
    url: str
    title: str
    snippet: str
    retrieved_at: str


@dataclass(frozen=True, slots=True)
class VulnBrief:
    cwe: str
    affected_function: str
    trigger: str
    expected_behaviour: str
    citations: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunEvidence:
    label: str
    outcome: str
    error_kind: str | None
    log_sha256: str
    test_sha256: str
    patch_sha256: str | None
    duration: float

    @classmethod
    def from_result(
        cls, label: str, result: RunResult, test_text: str, patch_text: str | None
    ) -> "RunEvidence":
        return cls(
            label,
            result.outcome,
            result.error_kind,
            result.log_sha256,
            sha256_text(test_text),
            sha256_text(patch_text) if patch_text is not None else None,
            result.duration,
        )


@dataclass(frozen=True, slots=True)
class MutationEvidence:
    reversal_killed: int
    reversal_total: int
    operator_killed: int
    operator_total: int
    score: float
    passed: bool
    survivors: tuple[str, ...]

    @classmethod
    def from_gate(cls, gate: GateResult) -> "MutationEvidence":
        return cls(
            gate.reversal_killed,
            gate.reversal_total,
            gate.operator_killed,
            gate.operator_total,
            gate.score,
            gate.passed,
            tuple(mutant.description for mutant in gate.survivors),
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    case_id: str
    cve: str
    package: str
    sources: tuple[Source, ...]
    brief: VulnBrief
    test_code: str
    diff: str
    red: RunEvidence
    green: RunEvidence
    regression: RunEvidence
    mutation: MutationEvidence

    def digest(self) -> str:
        payload = dataclasses.asdict(self)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return sha256_text(canonical)
