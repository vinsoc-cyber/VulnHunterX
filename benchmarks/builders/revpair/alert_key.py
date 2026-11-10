# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Line-shift-robust alert identity and cross-revision alert matching.

An alert on the vulnerable revision and an alert on the fix revision are "the
same alert" when they agree on the **primary key**::

    (tool, rule_id, repo-relative path [vuln side mapped through renames],
     enclosing function name or "", normalised source text of the flagged line)

Duplicates of one primary key (e.g. two identical ``free(p);`` lines in one
function) are paired in line order, so the key is effectively a multiset key.

The flagged-line text is read from each revision's own worktree so it is
comparable across tools; the scanner's ``region.snippet`` is only used when the
file cannot be read. Whitespace is collapsed with the same rule as
``vuln_hunter_x.context.anchor._norm``.

Remaining alerts are matched, in order, by

1. **secondary key** — CodeQL ``partialFingerprints.primaryLocationLineHash``
   (already occurrence-qualified by CodeQL), plus tool/rule/mapped path;
2. **diff-mapped line** — the vuln line mapped old→new through the diff hunks
   equals the fix-side line (same tool/rule/mapped path);
3. **hunk correspondence** — same tool/rule/mapped path/function and the vuln
   line lies in a modified hunk whose new-side range contains the fix-side line
   (the flagged line was edited but the alert persisted).

Function names come from SARIF ``logicalLocations`` when a scanner provides
them, else from :func:`enclosing_function`, a deliberately simple, dependency-
free heuristic (indentation-scoped ``def`` for Python; nearest preceding
signature-shaped line for brace languages). It may be wrong on unusual code;
it returns ``""`` rather than guessing when nothing plausible is found, which
only makes the key less specific — never mismatches across files.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from benchmarks.builders.revpair.hunks import DiffIndex
from vuln_hunter_x.core.types import Finding

_FUNC_SCAN_LIMIT = 400
_PY_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_KW_FUNC_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("  # JS
    r"|^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?\s*"
    r"([A-Za-z_]\w*)\s*\("  # PHP
    r"|^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\[(]"  # Go
)
_C_LIKE_RE = re.compile(
    r"^\s*(?:[\w:<>,\*&~\[\]]+\s+)*?[\*&\s]*([A-Za-z_~][\w:~]*)\s*\([^;]*$"  # name(...
)
_JS_ASSIGN_FUNC_RE = re.compile(
    r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*[=:]\s*(?:async\s+)?"
    r"(?:function\b|\([^)]*\)\s*=>)"
)
_NOT_FUNCS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "catch",
        "do",
        "else",
        "case",
        "new",
        "delete",
        "throw",
        "typeof",
        "defined",
        "elif",
        "with",
        "using",
        "lock",
        "foreach",
        "synchronized",
    }
)


def norm_text(text: str) -> str:
    """Collapse whitespace (same rule as ``vuln_hunter_x.context.anchor._norm``)."""
    return " ".join(text.split())


def norm_path(path: str, root: Path | None = None) -> str:
    """Repo-relative, forward-slash path for a SARIF URI.

    Mirrors ``verification.engine._norm_path``/``_repo_relative_path``: strips
    ``file://``, relativises absolute paths against ``root`` (the revision's
    worktree), and trims edge slashes. An absolute path outside ``root`` is
    returned normalised but unrelativised so it can never equal a relative one.
    """
    p = (path or "").strip()
    if p.startswith("file://"):
        p = p[len("file://") :]
    if root is not None and p.startswith("/"):
        for base in {str(root), str(Path(root).resolve())}:
            prefix = base.rstrip("/") + "/"
            if p.startswith(prefix):
                p = p[len(prefix) :]
                break
    return p.replace("\\", "/").strip("/")


def enclosing_function(lines: list[str], line: int, lang: str = "") -> str:
    """Best-effort name of the function enclosing 1-based ``line`` (``""`` if unknown)."""
    if line < 1 or line > len(lines):
        return ""
    idx = line - 1
    lo = max(0, idx - _FUNC_SCAN_LIMIT)
    if lang == "python":
        target_indent: int | None = None
        for i in range(idx, lo - 1, -1):
            text = lines[i]
            if not text.strip():
                continue
            indent = len(text) - len(text.lstrip())
            if target_indent is None:
                target_indent = indent
                m = _PY_DEF_RE.match(text)
                if m:
                    return m.group(2)
                continue
            m = _PY_DEF_RE.match(text)
            if m and len(m.group(1)) < target_indent:
                return m.group(2)
            if indent < target_indent and not text.lstrip().startswith(("#", "@", ")")):
                target_indent = indent
                if indent == 0:
                    return ""
        return ""
    for i in range(idx, lo - 1, -1):
        text = lines[i]
        stripped = text.strip()
        if not stripped or stripped.startswith(("//", "/*", "*", "#")):
            continue
        m = _KW_FUNC_RE.match(text)
        if m:
            return next(g for g in m.groups() if g)
        m = _JS_ASSIGN_FUNC_RE.match(text)
        if m:
            return m.group(1)
        if stripped.endswith(";"):
            continue
        m = _C_LIKE_RE.match(text)
        if m:
            name = m.group(1).split("::")[-1]
            if name not in _NOT_FUNCS and not stripped.startswith(("}", "=", ".", "->")):
                # Require a definition: '{' on this or one of the next 2 lines.
                window = " ".join(lines[i : i + 3])
                if "{" in window:
                    return name
    return ""


@dataclass
class Alert:
    """A scanner finding on one revision plus everything needed to key it."""

    finding: Finding
    path: str  # repo-relative on its own revision
    tool: str
    rule_id: str
    start_line: int
    end_line: int
    function: str = ""
    line_text: str = ""
    fingerprint: str = ""  # CodeQL primaryLocationLineHash, "" if absent

    def primary_key(self, path: str | None = None) -> tuple[str, str, str, str, str]:
        return (
            self.tool,
            self.rule_id,
            self.path if path is None else path,
            self.function,
            self.line_text,
        )


def key_str(key: tuple[str, ...]) -> str:
    """Stable printable digest of a key tuple."""
    raw = json.dumps(list(key), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _result_index(sarif_data: dict[str, Any]) -> dict[tuple[str, str, int, int], dict]:
    """Index raw SARIF results by (ruleId, uri, startLine, startColumn).

    ``SarifParser.parse_findings`` drops ``partialFingerprints`` and
    ``logicalLocations``; we read them back from the raw results here.
    """
    index: dict[tuple[str, str, int, int], dict] = {}
    for run in sarif_data.get("runs") or []:
        artifacts = run.get("artifacts") or []
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or ""
            for loc in result.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                uri = art.get("uri") or ""
                ai = art.get("index")
                if isinstance(ai, int) and 0 <= ai < len(artifacts):
                    uri = (artifacts[ai].get("location") or {}).get("uri") or uri
                region = phys.get("region") or {}
                k = (rule_id, uri, region.get("startLine") or 1, region.get("startColumn") or 0)
                fn = ""
                for ll in loc.get("logicalLocations") or []:
                    if ll.get("kind") in (None, "function", "member", "method"):
                        fn = ll.get("name") or ll.get("fullyQualifiedName") or ""
                        if fn:
                            break
                index.setdefault(
                    k,
                    {
                        "fingerprint": (result.get("partialFingerprints") or {}).get(
                            "primaryLocationLineHash", ""
                        ),
                        "function": fn,
                    },
                )
    return index


class SourceCache:
    """Reads (and caches) file lines of one revision's worktree, repo-scoped."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, rel_path: str) -> list[str] | None:
        if rel_path in self._cache:
            return self._cache[rel_path]
        result: list[str] | None = None
        try:
            target = (self.root / rel_path).resolve()
            target.relative_to(self.root)  # refuse traversal / symlink escapes
            if target.is_file():
                result = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except (ValueError, OSError):
            result = None
        self._cache[rel_path] = result
        return result


def build_alerts(
    findings: list[Finding],
    sarif_data: dict[str, Any] | None,
    source: SourceCache,
) -> list[Alert]:
    """Turn parsed findings of one revision into keyed :class:`Alert` objects."""
    index = _result_index(sarif_data or {})
    alerts: list[Alert] = []
    for f in findings:
        rel = norm_path(f.file, source.root)
        raw = index.get((f.rule_id, f.file, f.start_line, f.start_column), {})
        lines = source.lines(rel) if rel else None
        text = ""
        if lines is not None and 1 <= f.start_line <= len(lines):
            text = norm_text(lines[f.start_line - 1])
        elif f.sink_snippet:
            text = norm_text(next((s for s in f.sink_snippet.splitlines() if s.strip()), ""))
        function = raw.get("function") or (
            enclosing_function(lines, f.start_line, f.lang) if lines else ""
        )
        alerts.append(
            Alert(
                finding=f,
                path=rel,
                tool=f.tool,
                rule_id=f.rule_id,
                start_line=f.start_line,
                end_line=max(f.end_line, f.start_line),
                function=function,
                line_text=text,
                fingerprint=raw.get("fingerprint", ""),
            )
        )
    return alerts


@dataclass
class MatchResult:
    """Outcome of matching vulnerable-side alerts against fix-side alerts."""

    pairs: list[tuple[Alert, Alert, str]] = field(default_factory=list)  # (vuln, fix, how)
    vuln_unmatched: list[Alert] = field(default_factory=list)
    fix_unmatched: list[Alert] = field(default_factory=list)

    def match_kind(self, vuln: Alert) -> str | None:
        for v, _f, how in self.pairs:
            if v is vuln:
                return how
        return None


def mapped_path(alert: Alert, diff: DiffIndex) -> str | None:
    """Vuln-side path translated to the fix revision (``None`` if deleted)."""
    return diff.rename_old_to_new(alert.path)


def match_alerts(vuln: list[Alert], fix: list[Alert], diff: DiffIndex) -> MatchResult:
    """Pair vuln-side and fix-side alerts (see module docstring for the order)."""
    result = MatchResult()
    vuln_left = sorted(vuln, key=lambda a: (a.path, a.start_line, a.rule_id))
    fix_left = sorted(fix, key=lambda a: (a.path, a.start_line, a.rule_id))

    def run_pass(how: str, vkey: Any, fkey: Any) -> None:
        nonlocal vuln_left, fix_left
        buckets: dict[Any, list[Alert]] = defaultdict(list)
        for a in fix_left:
            k = fkey(a)
            if k is not None:
                buckets[k].append(a)
        used: set[int] = set()
        remaining: list[Alert] = []
        for a in vuln_left:
            k = vkey(a)
            bucket = buckets.get(k) if k is not None else None
            if bucket:
                partner = bucket.pop(0)
                used.add(id(partner))
                result.pairs.append((a, partner, how))
            else:
                remaining.append(a)
        vuln_left = remaining
        fix_left = [a for a in fix_left if id(a) not in used]

    def vprimary(a: Alert) -> Any:
        p = mapped_path(a, diff)
        return None if p is None else a.primary_key(p)

    run_pass("primary", vprimary, lambda a: a.primary_key())

    def vfp(a: Alert) -> Any:
        p = mapped_path(a, diff)
        if p is None or not a.fingerprint:
            return None
        return (a.tool, a.rule_id, p, a.fingerprint)

    run_pass(
        "fingerprint",
        vfp,
        lambda a: (a.tool, a.rule_id, a.path, a.fingerprint) if a.fingerprint else None,
    )

    def vline(a: Alert) -> Any:
        p, line = diff.map_old_line(a.path, a.start_line)
        if p is None or line is None:
            return None
        return (a.tool, a.rule_id, p, line)

    run_pass("line", vline, lambda a: (a.tool, a.rule_id, a.path, a.start_line))

    # Hunk correspondence: the flagged line was edited, yet the same rule still
    # fires inside the replacement lines of that hunk in the same function.
    remaining: list[Alert] = []
    for a in vuln_left:
        fd = diff.for_old_path(a.path)
        hunk = fd.hunk_for_old_line(a.start_line) if fd else None
        partner = None
        if fd is not None and hunk is not None and hunk.new_count > 0:
            for b in fix_left:
                if (
                    b.tool == a.tool
                    and b.rule_id == a.rule_id
                    and b.path == fd.new_path
                    and b.function == a.function
                    and hunk.new_start <= b.start_line <= hunk.new_end
                ):
                    partner = b
                    break
        if partner is not None:
            fix_left.remove(partner)
            result.pairs.append((a, partner, "hunk"))
        else:
            remaining.append(a)
    result.vuln_unmatched = remaining
    result.fix_unmatched = fix_left
    return result
