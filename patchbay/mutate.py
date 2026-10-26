"""Patch-aware mutation testing for generated regression tests."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path

from .diffutil import added_lines, apply, normalize, parse, revert_hunk
from .sandbox import RunResult, run_pytest


class GateError(RuntimeError):
    """The supplied patch/test pair is not eligible for mutation testing."""


@dataclass(frozen=True, slots=True)
class Mutant:
    kind: str
    description: str
    line: int
    text: str


@dataclass(frozen=True, slots=True)
class GateResult:
    passed: bool
    reversal_killed: int
    reversal_total: int
    operator_killed: int
    operator_total: int
    score: float
    survivors: list[Mutant]
    results: list[tuple[Mutant, RunResult]]


def _offsets(text: str) -> list[int]:
    result = [0]
    for line in text.splitlines(keepends=True):
        result.append(result[-1] + len(line))
    return result


def _span(offsets: list[int], start: tuple[int, int], end: tuple[int, int]) -> tuple[int, int]:
    return offsets[start[0] - 1] + start[1], offsets[end[0] - 1] + end[1]


def _replace(text: str, start: int, end: int, replacement: str) -> str:
    return text[:start] + replacement + text[end:]


def _operator_candidates(patched: str, added: set[int]) -> list[tuple[str, int, str]]:
    offsets = _offsets(patched)
    tokens = list(tokenize.generate_tokens(io.StringIO(patched).readline))
    candidates: list[tuple[str, int, str]] = []

    def replace_token(token: tokenize.TokenInfo, value: str, description: str) -> None:
        if token.start[0] in added:
            start, end = _span(offsets, token.start, token.end)
            candidates.append((description, token.start[0], _replace(patched, start, end, value)))

    for index, token in enumerate(tokens):
        if token.type == tokenize.OP and token.string in {"<", "<=", ">", ">=", "==", "!="}:
            replace_token(
                token,
                {"<": "<=", "<=": "<", ">": ">=", ">=": ">", "==": "!=", "!=": "=="}[token.string],
                f"flip comparison {token.string}",
            )
        elif token.type == tokenize.NAME and token.string in {"and", "or"}:
            replace_token(token, "or" if token.string == "and" else "and", f"flip {token.string}")
        elif token.type == tokenize.NAME and token.string == "in":
            previous = tokens[index - 1] if index else None
            if not (previous and previous.type == tokenize.NAME and previous.string == "not"):
                replace_token(token, "not in", "flip in")
        elif token.type == tokenize.NAME and token.string == "is":
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if not (following and following.type == tokenize.NAME and following.string == "not"):
                replace_token(token, "is not", "flip is")
        elif token.type == tokenize.NAME and token.string == "not":
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if following and following.type == tokenize.NAME and following.string == "in":
                if token.start[0] in added:
                    start, end = _span(offsets, token.start, following.end)
                    candidates.append(("flip not in", token.start[0], _replace(patched, start, end, "in")))
            else:
                replace_token(token, "", "drop not")
        elif token.type == tokenize.NUMBER and token.start[0] in added and re.fullmatch(r"[0-9][0-9_]*", token.string):
            value = int(token.string.replace("_", ""))
            for delta in (-1, 1):
                start, end = _span(offsets, token.start, token.end)
                candidates.append((f"change integer {token.string} by {delta:+d}", token.start[0], _replace(patched, start, end, str(value + delta))))

    tree = ast.parse(patched)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Raise, ast.Return)) and node.lineno in added:
            start = offsets[node.lineno - 1] + node.col_offset
            end = offsets[node.end_lineno - 1] + node.end_col_offset
            kind = "raise" if isinstance(node, ast.Raise) else "return"
            candidates.append((f"replace {kind} guard with pass", node.lineno, _replace(patched, start, end, "pass")))
    return candidates


OPERATOR_THRESHOLD = 0.8


def gate_passes(reversal_killed: int, reversal_total: int, operator_killed: int, operator_total: int) -> bool:
    """Every hunk reversal killed and at least 80 % of operator mutants killed."""
    return reversal_killed == reversal_total and (
        operator_total == 0 or operator_killed / operator_total >= OPERATOR_THRESHOLD
    )


def generate_mutants(original: str, diff: str) -> list[Mutant]:
    """Create hunk reversals and safe token-level mutations of added lines."""
    diff = normalize(original, diff)
    patched = apply(original, diff)
    mutants: list[Mutant] = []
    for index, hunk in enumerate(parse(diff)):
        mutants.append(
            Mutant("hunk_reversal", f"revert hunk {index + 1}", hunk.new_start, revert_hunk(patched, diff, index))
        )
    for description, line, text in _operator_candidates(patched, set(added_lines(diff))):
        mutants.append(Mutant("operator", description, line, text))

    result: list[Mutant] = []
    seen = {patched}
    for mutant in mutants:
        if mutant.text in seen:
            continue
        try:
            compile(mutant.text, "<mutant>", "exec")
        except (SyntaxError, ValueError):
            continue
        seen.add(mutant.text)
        result.append(mutant)
    return result


def run_gate(
    workdir: Path,
    target: str,
    original: str,
    diff: str,
    test_files: dict[str, str],
    test_path: str,
    timeout: float,
) -> GateResult:
    """Run the baseline and every patch-aware mutant in the sandbox."""
    diff = normalize(original, diff)
    patched = apply(original, diff)
    baseline_files = {target: patched, **test_files}
    baseline = run_pytest(workdir, baseline_files, test_path, timeout)
    if baseline.outcome != "passed":
        raise GateError(f"patched test must pass before mutation testing ({baseline.outcome})")

    mutants = generate_mutants(original, diff)
    results: list[tuple[Mutant, RunResult]] = []
    for mutant in mutants:
        result = run_pytest(workdir, {target: mutant.text, **test_files}, test_path, timeout)
        results.append((mutant, result))
    reversals = [(mutant, result) for mutant, result in results if mutant.kind == "hunk_reversal"]
    operators = [(mutant, result) for mutant, result in results if mutant.kind == "operator"]
    reversal_killed = sum(result.outcome != "passed" for _, result in reversals)
    operator_killed = sum(result.outcome != "passed" for _, result in operators)
    reversal_total, operator_total = len(reversals), len(operators)
    score = (reversal_killed + operator_killed) / len(results) if results else 1.0
    passed = gate_passes(reversal_killed, reversal_total, operator_killed, operator_total)
    survivors = [mutant for mutant, result in results if result.outcome == "passed"]
    return GateResult(
        passed,
        reversal_killed,
        reversal_total,
        operator_killed,
        operator_total,
        score,
        survivors,
        results,
    )
