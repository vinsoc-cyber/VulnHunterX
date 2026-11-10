# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Minimal parser for ``git diff -U0 -M`` output.

Only what the revision-pair labeller needs is extracted: per changed file the
old/new path (renames resolved), the hunks with their old-side and new-side
line ranges, and an old→new line mapping that returns ``None`` for lines inside
a deleted/modified region.

Hunk semantics with ``-U0`` (no context lines):

* ``@@ -a,b +c,d @@`` with ``b > 0`` — old lines ``a .. a+b-1`` were deleted or
  modified; with ``d > 0`` new lines ``c .. c+d-1`` were added.
* ``b == 0`` — a pure insertion *after* old line ``a`` (``a == 0`` means at the
  top of the file).
* A missing count means ``1``.

The parser tracks the expected number of body lines per hunk so a removed
content line that itself starts with ``-- `` (e.g. a SQL comment) can never be
mistaken for a ``--- `` file header. No third-party dependency is used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_HEADER = "diff --git "

_C_ESCAPES = {
    "a": 0x07,
    "b": 0x08,
    "t": 0x09,
    "n": 0x0A,
    "v": 0x0B,
    "f": 0x0C,
    "r": 0x0D,
    '"': 0x22,
    "\\": 0x5C,
}


def unquote_git_path(raw: str) -> str:
    """Undo git's C-style path quoting (``"a/tab\\there"``); plain paths pass through."""
    if len(raw) < 2 or not (raw.startswith('"') and raw.endswith('"')):
        return raw
    body = raw[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _C_ESCAPES:
            out.append(_C_ESCAPES[nxt])
            i += 2
        elif re.match(r"[0-7]{3}", body[i + 1 : i + 4]):
            out.append(int(body[i + 1 : i + 4], 8) & 0xFF)
            i += 4
        else:
            out.extend(nxt.encode("utf-8"))
            i += 2
    return out.decode("utf-8", errors="replace")


def _strip_prefix(path: str, prefix: str) -> str | None:
    path = unquote_git_path(path.rstrip("\t"))
    if path == "/dev/null":
        return None
    return path[len(prefix) :] if path.startswith(prefix) else path


@dataclass(frozen=True)
class Hunk:
    """One ``-U0`` hunk. Counts may be zero (pure insertion / pure deletion)."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int

    @property
    def old_end(self) -> int:
        """Last old-side line changed (``old_start - 1`` for a pure insertion)."""
        return self.old_start + self.old_count - 1

    @property
    def new_end(self) -> int:
        return self.new_start + self.new_count - 1

    def old_lines(self) -> range:
        """Old-side lines deleted or modified by this hunk (empty for insertions)."""
        return range(self.old_start, self.old_start + self.old_count)

    def new_lines(self) -> range:
        """New-side lines added by this hunk (empty for pure deletions)."""
        return range(self.new_start, self.new_start + self.new_count)


@dataclass
class FileDiff:
    """Changes to one file between two revisions."""

    old_path: str | None  # None for a newly added file
    new_path: str | None  # None for a deleted file
    hunks: list[Hunk] = field(default_factory=list)
    is_binary: bool = False

    @property
    def status(self) -> str:
        if self.old_path is None:
            return "added"
        if self.new_path is None:
            return "deleted"
        if self.old_path != self.new_path:
            return "renamed"
        return "modified"

    @property
    def deleted_ranges(self) -> list[tuple[int, int]]:
        """Inclusive old-side ``(start, end)`` ranges deleted or modified."""
        return [(h.old_start, h.old_end) for h in self.hunks if h.old_count > 0]

    @property
    def added_ranges(self) -> list[tuple[int, int]]:
        """Inclusive new-side ``(start, end)`` ranges added."""
        return [(h.new_start, h.new_end) for h in self.hunks if h.new_count > 0]

    @property
    def insertion_points(self) -> list[int]:
        """Old-side lines *after which* new lines were purely inserted."""
        return [h.old_start for h in self.hunks if h.old_count == 0]

    def changed_old_lines(self) -> set[int]:
        out: set[int] = set()
        for h in self.hunks:
            out.update(h.old_lines())
        return out

    def hunk_for_old_line(self, line: int) -> Hunk | None:
        """The hunk whose deleted/modified old range contains ``line``."""
        for h in self.hunks:
            if h.old_count > 0 and h.old_start <= line <= h.old_end:
                return h
        return None

    def overlaps_old(self, start: int, end: int, *, include_insertions: bool = True) -> bool:
        """True if old-side ``[start, end]`` intersects a deleted/modified range.

        With ``include_insertions`` a pure insertion placed directly before the
        span or inside it (insertion point in ``[start - 1, end - 1]``) also
        counts — the canonical "add a bounds check before the sink" fix.
        """
        end = max(start, end)
        for h in self.hunks:
            if h.old_count > 0:
                if h.old_start <= end and h.old_end >= start:
                    return True
            elif include_insertions and start - 1 <= h.old_start <= end - 1:
                return True
        return False

    def map_old_to_new(self, line: int) -> int | None:
        """Map an old-side line to its new-side number, or ``None`` if it changed.

        Returns ``None`` when the file was deleted or ``line`` lies in a
        deleted/modified region; otherwise shifts ``line`` by the net line delta
        of every hunk located entirely before it.
        """
        if self.new_path is None:
            return None
        delta = 0
        for h in self.hunks:
            if h.old_count > 0:
                if h.old_start <= line <= h.old_end:
                    return None
                if h.old_end < line:
                    delta += h.new_count - h.old_count
            elif h.old_start < line:
                delta += h.new_count
        return line + delta


@dataclass
class DiffIndex:
    """All file diffs of one commit range, indexed by old and new path."""

    files: list[FileDiff] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._by_old = {f.old_path: f for f in self.files if f.old_path is not None}
        self._by_new = {f.new_path: f for f in self.files if f.new_path is not None}

    def for_old_path(self, path: str) -> FileDiff | None:
        return self._by_old.get(path)

    def for_new_path(self, path: str) -> FileDiff | None:
        return self._by_new.get(path)

    def rename_old_to_new(self, path: str) -> str | None:
        """New path of old ``path``: unchanged if untouched, ``None`` if deleted."""
        fd = self._by_old.get(path)
        if fd is None:
            return path
        return fd.new_path

    def map_old_line(self, path: str, line: int) -> tuple[str | None, int | None]:
        """Map ``(old path, old line)`` to ``(new path, new line)``."""
        fd = self._by_old.get(path)
        if fd is None:
            return path, line
        return fd.new_path, fd.map_old_to_new(line)

    @property
    def changed_old_paths(self) -> set[str]:
        return set(self._by_old)


def _parse_header_paths(header: str) -> tuple[str | None, str | None]:
    """Best-effort ``diff --git a/X b/Y`` split, used when no ---/+++ lines exist."""
    rest = header[len(_DIFF_HEADER) :]
    if rest.startswith('"'):
        m = re.match(r'^("(?:[^"\\]|\\.)*") (.+)$', rest)
        if m:
            return _strip_prefix(m.group(1), "a/"), _strip_prefix(m.group(2), "b/")
        return None, None
    # Unquoted and identical on both sides: "a/P b/P" has odd length 2*len(P)+5.
    n = len(rest)
    if n % 2 == 1:
        half = (n - 1) // 2
        left, right = rest[:half], rest[half + 1 :]
        if left.startswith("a/") and right.startswith("b/") and left[2:] == right[2:]:
            return left[2:], right[2:]
    parts = rest.split(" b/", 1)
    if len(parts) == 2 and parts[0].startswith("a/"):
        return parts[0][2:], parts[1]
    return None, None


def parse_unified_diff(text: str) -> DiffIndex:
    """Parse ``git diff -U0 -M`` output into a :class:`DiffIndex`."""
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    header_paths: tuple[str | None, str | None] = (None, None)
    saw_minus = saw_plus = False
    added = deleted = False
    rename_from: str | None = None
    rename_to: str | None = None
    remaining_old = remaining_new = 0

    def finish() -> None:
        nonlocal cur
        if cur is None:
            return
        if rename_from is not None:
            cur.old_path = rename_from
        if rename_to is not None:
            cur.new_path = rename_to
        if not saw_minus and rename_from is None:
            cur.old_path = None if added else header_paths[0]
        if not saw_plus and rename_to is None:
            cur.new_path = None if deleted else header_paths[1]
        if cur.old_path is not None or cur.new_path is not None:
            files.append(cur)
        cur = None

    for line in text.splitlines():
        if remaining_old > 0 or remaining_new > 0:
            if line.startswith("-") and remaining_old > 0:
                remaining_old -= 1
                continue
            if line.startswith("+") and remaining_new > 0:
                remaining_new -= 1
                continue
            if line.startswith("\\"):
                continue
            # Malformed/truncated hunk: fall through and resynchronise on headers.
            remaining_old = remaining_new = 0
        if line.startswith("\\"):
            continue  # "\ No newline at end of file"
        if line.startswith(_DIFF_HEADER):
            finish()
            cur = FileDiff(old_path=None, new_path=None)
            header_paths = _parse_header_paths(line)
            saw_minus = saw_plus = added = deleted = False
            rename_from = rename_to = None
            continue
        if cur is None:
            continue
        if line.startswith("new file mode"):
            added = True
        elif line.startswith("deleted file mode"):
            deleted = True
        elif line.startswith("rename from "):
            rename_from = unquote_git_path(line[len("rename from ") :])
        elif line.startswith("rename to "):
            rename_to = unquote_git_path(line[len("rename to ") :])
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            cur.is_binary = True
        elif line.startswith("--- "):
            cur.old_path = _strip_prefix(line[4:], "a/")
            saw_minus = True
        elif line.startswith("+++ "):
            cur.new_path = _strip_prefix(line[4:], "b/")
            saw_plus = True
        else:
            m = _HUNK_RE.match(line)
            if m:
                old_count = int(m.group(2)) if m.group(2) is not None else 1
                new_count = int(m.group(4)) if m.group(4) is not None else 1
                cur.hunks.append(Hunk(int(m.group(1)), old_count, int(m.group(3)), new_count))
                remaining_old, remaining_new = old_count, new_count
    finish()
    return DiffIndex(files)
