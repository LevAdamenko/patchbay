"""Small, strict unified-diff helpers used by the mutation gate."""

from __future__ import annotations

import re
from dataclasses import dataclass


class PatchError(ValueError):
    """A unified diff cannot be applied to the supplied text."""


@dataclass(frozen=True, slots=True)
class Hunk:
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    lines: tuple[str, ...]


_HUNK = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_lines>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_lines>\d+))? @@(?:.*)$"
)


def parse(diff: str) -> list[Hunk]:
    """Parse the hunks in a single-file unified diff.

    Hunk lines retain their leading `` ``, ``+`` or ``-`` marker and their
    original line ending.  File header lines are deliberately not hunks.
    """
    hunks: list[Hunk] = []
    current: Hunk | None = None
    current_lines: list[str] = []
    for line in diff.splitlines(keepends=True):
        match = _HUNK.match(line.rstrip("\r\n"))
        if match:
            if current is not None:
                hunks.append(
                    Hunk(
                        current.old_start,
                        current.old_lines,
                        current.new_start,
                        current.new_lines,
                        tuple(current_lines),
                    )
                )
            current = Hunk(
                int(match["old_start"]),
                int(match["old_lines"] or 1),
                int(match["new_start"]),
                int(match["new_lines"] or 1),
                (),
            )
            current_lines = []
        elif current is not None:
            if line.startswith((" ", "+", "-")):
                current_lines.append(line)
            elif line.startswith("\\ No newline at end of file"):
                continue
            else:
                raise PatchError(f"unexpected line in hunk: {line!r}")
    if current is not None:
        hunks.append(
            Hunk(
                current.old_start,
                current.old_lines,
                current.new_start,
                current.new_lines,
                tuple(current_lines),
            )
        )
    if not hunks:
        raise PatchError("diff contains no hunks")
    return hunks


def _check_counts(hunks: list[Hunk]) -> None:
    for index, hunk in enumerate(hunks):
        old_count = sum(line.startswith((" ", "-")) for line in hunk.lines)
        new_count = sum(line.startswith((" ", "+")) for line in hunk.lines)
        if (old_count, new_count) != (hunk.old_lines, hunk.new_lines):
            raise PatchError(f"hunk {index} line counts do not match its header")


def _locate(source: list[str], wanted: list[str], hint: int, cursor: int) -> int | None:
    """Index where *wanted* occurs at or after *cursor*, nearest to *hint*."""
    starts = [
        start
        for start in range(cursor, len(source) - len(wanted) + 1)
        if source[start : start + len(wanted)] == wanted
    ]
    return min(starts, key=lambda start: abs(start - hint)) if starts else None


def normalize(original_text: str, diff: str) -> str:
    """Rewrite hunk headers so they match where each hunk really applies.

    Hand- and model-written diffs often carry wrong line numbers or counts
    while their content is right (GNU ``patch`` tolerates this). Hunks are
    located by their exact old-side lines, nearest to the stated position;
    content is never fuzzed. Raises :class:`PatchError` if a hunk is absent.
    """
    source = original_text.splitlines(keepends=True)
    headers = [line for line in diff.splitlines(keepends=True) if line.startswith(("--- ", "+++ "))][:2]
    output = list(headers)
    cursor = 0
    offset = 0
    for index, hunk in enumerate(parse(diff)):
        wanted = _side(hunk, "-")
        start = _locate(source, wanted, hunk.old_start - 1, cursor)
        if start is None:
            raise PatchError(f"hunk {index} context does not occur in the supplied text")
        old_count, new_count = len(wanted), len(_side(hunk, "+"))
        output.append(f"@@ -{start + 1},{old_count} +{start + 1 + offset},{new_count} @@\n")
        output.extend(line if line.endswith("\n") else line + "\n" for line in hunk.lines)
        cursor = start + old_count
        offset += new_count - old_count
    return "".join(output)


# Friendly names for callers that prefer an explicit parser name.
parse_diff = parse_unified_diff = parse


def _side(hunk: Hunk, marker: str) -> list[str]:
    return [line[1:] for line in hunk.lines if line[0] in (" ", marker)]


def _apply_hunks(text: str, hunks: list[Hunk], *, reverse: int | None = None) -> str:
    source = text.splitlines(keepends=True)
    output: list[str] = []
    cursor = 0
    for index, hunk in enumerate(hunks):
        is_reverse = index == reverse
        start = (hunk.new_start if is_reverse else hunk.old_start) - 1
        wanted = _side(hunk, "+" if is_reverse else "-")
        replacement = _side(hunk, "-" if is_reverse else "+")
        if start < cursor or start > len(source):
            raise PatchError(f"hunk {index} is out of order or outside the file")
        output.extend(source[cursor:start])
        actual = source[start : start + len(wanted)]
        if actual != wanted:
            raise PatchError(f"hunk {index} context does not match the supplied text")
        output.extend(replacement)
        cursor = start + len(wanted)
    output.extend(source[cursor:])
    return "".join(output)


def apply(original_text: str, diff: str) -> str:
    """Apply *diff* strictly, raising :class:`PatchError` on any mismatch."""
    hunks = parse(diff)
    _check_counts(hunks)
    return _apply_hunks(original_text, hunks)


def revert_hunk(patched_text: str, diff: str, index: int) -> str:
    """Undo only hunk *index* in an otherwise patched file."""
    hunks = parse(diff)
    if not 0 <= index < len(hunks):
        raise IndexError(f"hunk index out of range: {index}")
    hunk = hunks[index]
    source = patched_text.splitlines(keepends=True)
    start = hunk.new_start - 1
    wanted = _side(hunk, "+")
    actual = source[start : start + len(wanted)]
    if actual != wanted:
        raise PatchError(f"hunk {index} context does not match the supplied text")
    return "".join(source[:start] + _side(hunk, "-") + source[start + len(wanted) :])


def added_lines(diff: str) -> list[int]:
    """Return one-based destination-file numbers for all added lines."""
    result: list[int] = []
    for hunk in parse(diff):
        line_number = hunk.new_start
        for line in hunk.lines:
            if line.startswith("+"):
                result.append(line_number)
                line_number += 1
            elif line.startswith(" "):
                line_number += 1
    return result


def touched_paths(diff: str) -> list[str]:
    """Return paths named by the diff headers, without a/b prefixes."""
    paths: list[str] = []
    for line in diff.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        path = line[4:].split("\t", 1)[0]
        if path == "/dev/null":
            continue
        if path.startswith(("a/", "b/")):
            path = path[2:]
        if path not in paths:
            paths.append(path)
    return paths
