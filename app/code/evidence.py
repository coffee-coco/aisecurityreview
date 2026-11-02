"""Check that code quoted as evidence by an AI finding really exists in the uploaded file - no LLM involved.

Matching tolerates whitespace (indentation depth, tabs vs spaces, trailing space, blank lines added or
dropped), whole-line comments the model left out, code fences and the ``  12| `` line-number gutter the
review prompt adds. It deliberately does not tolerate changes to case, punctuation or quotes: a model that
rewrote those did not quote the code. An unverified snippet never removes a finding; it is only flagged.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from itertools import pairwise
from pathlib import Path

MAX_SNIPPET_CHARS = 2_000
MAX_SNIPPET_LINES = 60
MIN_SNIPPET_CHARS = 5      # shorter needles (`}`, `def`) would match almost any file
MAX_VERIFY_BYTES = 1_048_576
MAX_COMMENT_SKIP = 20      # elided comment lines stepped over between two matched code lines

_GUTTER_RE = re.compile(r"^ *(\d+)(?:\t|\| ?)")
_FENCE_OPEN_RE = re.compile(r"^\s*```[\w.+-]*\s*$")
_FENCE_CLOSE_RE = re.compile(r"^\s*```\s*$")
_COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*/|\*|<!--|--|;)")


@dataclass(frozen=True)
class EvidenceCheck:
    verified: bool
    start_line: int | None = None  # 1-based inclusive, only when verified
    end_line: int | None = None
    occurrences: int = 0
    reason: str = ""


def verify_snippet(path: Path, snippet: str) -> EvidenceCheck:
    """Locate ``snippet`` in the file at ``path``. Never raises."""
    if len(snippet) > MAX_SNIPPET_CHARS or snippet.count("\n") + 1 > MAX_SNIPPET_LINES:
        return EvidenceCheck(False, reason="snippet too long to verify")
    try:
        stat = path.stat()
        if not path.is_file():
            return EvidenceCheck(False, reason="not a file in the uploaded code")
        if stat.st_size > MAX_VERIFY_BYTES:
            return EvidenceCheck(False, reason="file too large to verify")
        haystack = _compacted(str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return EvidenceCheck(False, reason="file could not be read")
    needles = [n for n in _candidate_needles(snippet) if sum(map(len, n)) >= MIN_SNIPPET_CHARS]
    if not needles:
        return EvidenceCheck(False, reason="snippet empty or too short to identify the code")
    for needle in needles:
        match = _find(haystack, needle)
        if match:
            return EvidenceCheck(True, *match)
    return EvidenceCheck(False, reason="snippet not found in the file")


def _normalise_line(line: str) -> str:
    return " ".join(unicodedata.normalize("NFC", line).split())


@lru_cache(maxsize=64)
def _compacted(path_str: str, mtime_ns: int, size: int) -> tuple[tuple[str, int, bool], ...]:
    """Normalised non-blank lines of a file: (text, 1-based line number, is-comment). Keyed on mtime/size."""
    out = []
    for n, line in enumerate(Path(path_str).read_text(errors="replace").splitlines(), 1):
        norm = _normalise_line(line)
        if norm:
            out.append((norm, n, bool(_COMMENT_RE.match(line))))
    return tuple(out)


def _candidate_needles(snippet: str) -> list[list[str]]:
    lines = snippet.splitlines()
    if lines and _FENCE_OPEN_RE.match(lines[0]):
        lines = lines[1:]
        if lines and _FENCE_CLOSE_RE.match(lines[-1]):
            lines = lines[:-1]
    out: list[list[str]] = []
    for lenient in (False, True):
        needle = [norm for line in _strip_gutter(lines, lenient) if (norm := _normalise_line(line))]
        if needle and needle not in out:
            out.append(needle)
    return out


def _strip_gutter(lines: list[str], lenient: bool) -> list[str]:
    """Remove a line-number gutter only when every non-blank line has one and the numbers run in order."""
    body = [line for line in lines if line.strip()]
    matches = [_GUTTER_RE.match(line) for line in body]
    if not body or not all(matches):
        return lines
    nums = [int(m.group(1)) for m in matches if m]
    ok = all(b > a for a, b in pairwise(nums)) if lenient else all(b - a == 1 for a, b in pairwise(nums))
    if len(nums) > 1 and not ok:
        return lines
    return [_GUTTER_RE.sub("", line, count=1) if line.strip() else line for line in lines]


def _find(haystack: tuple[tuple[str, int, bool], ...], needle: list[str]) -> tuple[int, int, int] | None:
    """(start_line, end_line, occurrences) of the first match."""
    if len(needle) == 1:
        exact = [n for text, n, _ in haystack if text == needle[0]]
        if exact:
            return exact[0], exact[0], len(exact)
        partial = [n for text, n, _ in haystack if needle[0] in text]  # fragment of a longer line
        return (partial[0], partial[0], len(partial)) if partial else None
    hits = []
    for i, (text, n, _) in enumerate(haystack):
        if text == needle[0]:
            end = _match_run(haystack, i, needle)
            if end is not None:
                hits.append((n, end))
    return (hits[0][0], hits[0][1], len(hits)) if hits else None


def _match_run(haystack: tuple[tuple[str, int, bool], ...], start: int, needle: list[str]) -> int | None:
    j, k, skipped = start + 1, 1, 0
    while k < len(needle) and j < len(haystack):
        text, _, is_comment = haystack[j]
        if text == needle[k]:
            k, j, skipped = k + 1, j + 1, 0
        elif is_comment and skipped < MAX_COMMENT_SKIP:
            j, skipped = j + 1, skipped + 1
        else:
            return None
    return haystack[j - 1][1] if k == len(needle) else None
