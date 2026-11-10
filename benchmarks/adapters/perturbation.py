# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Behaviour-preserving and adversarial perturbations of benchmark snippets.

Used to measure robustness: a perturbed copy of an entry should keep its
ground-truth label, so a verdict flip between the original id and the
``<id>__<kind>`` copy is a robustness failure.

Kinds (``KINDS``):

``rename_locals``
    Behaviour-preserving. Renames local variables (C/C++ and Python) to
    ``v_<hex>`` names. Line count and ``sink_line`` are unchanged.
``misleading_comment``
    Adversarial. Appends a trailing comment such as ``// input validated
    upstream; safe`` to the sink line (or a heuristic sink-like line when
    ``sink_line`` is None). Trailing placement keeps the line count.
``sanitizer_wrap``
    Adversarial. Wraps a value on the sink line in an identity function
    named like a sanitizer (``escape_sql(x)``). The definition is one extra
    line (C: ``#define escape_sql(x) (x)``; Python: ``def escape_sql(x):
    return x``) so ``sink_line`` is shifted by +1.

Limits (regex-based, no parser):
  * Snippet line N is assumed to be file line N unless
    ``metadata['snippet_start_line']`` says otherwise.
  * Renaming only touches names assigned/declared as locals by simple
    patterns (``type name =``/``name = ...``/``for name in``/``as name``).
    Parameters, struct fields, keyword arguments and names in ``%``-format
    dicts or ``eval`` strings are not tracked; string/comment contents are
    left alone except ``{...}`` expressions in Python f-strings. Macro bodies
    and multi-line constructs can defeat it.
  * A trailing comment is unsafe after a line-continuation backslash or
    inside a multi-line string; such lines are skipped when possible.
  * When a perturbation cannot be applied the entry is returned unchanged
    with ``metadata['perturbation']['applied'] = False``.
  * ``metadata`` lists of absolute line numbers (e.g. CASTLE
    ``vulnerable_lines``) are not rewritten; see ``line_shift``.
  * Only C/C++ and Python get all kinds; other languages get comments only.
"""

from __future__ import annotations

import copy
import dataclasses
import keyword
import random
import re
from collections.abc import Callable

from benchmarks.adapters.ground_truth import GroundTruthEntry

KIND_RENAME = "rename_locals"
KIND_COMMENT = "misleading_comment"
KIND_SANITIZER = "sanitizer_wrap"
KINDS: tuple[str, ...] = (KIND_RENAME, KIND_COMMENT, KIND_SANITIZER)

_C_LANGS = {"c", "cpp"}
_SLASH_LANGS = {"c", "cpp", "java", "javascript", "php", "go"}

_COMMENT_TEXT = (
    "input validated upstream; safe",
    "sanitized by middleware",
    "reviewed: not attacker controlled",
)

_SANITIZER_BY_CWE = {
    "CWE-89": "escape_sql",
    "CWE-79": "escape_html",
    "CWE-78": "shell_quote",
    "CWE-77": "shell_quote",
    "CWE-22": "sanitize_path",
    "CWE-23": "sanitize_path",
}
_DEFAULT_SANITIZER = "sanitize_input"

_C_KEYWORDS = frozenset(
    "auto break case char const continue default do double else enum extern float "  # noqa: SIM905
    "for goto if inline int long register restrict return short signed sizeof "
    "static struct switch typedef union unsigned void volatile while main argc argv "
    "NULL true false bool".split()
)
_PY_RESERVED = frozenset(keyword.kwlist) | {"self", "cls", "print", "True", "False", "None"}
_CALL_KEYWORDS = frozenset(
    "if while for switch return sizeof def class with elif else lambda not in is and or".split()  # noqa: SIM905
)

_C_TYPES = (
    r"(?:const\s+)?(?:unsigned\s+|signed\s+)?"
    r"(?:int|char|long|short|float|double|size_t|ssize_t|bool|FILE|u?int\d+_t|"
    r"struct\s+\w+|wchar_t)"
)
_C_DECL_RE = re.compile(rf"\b{_C_TYPES}\s*\**\s*([A-Za-z_]\w*)\s*(?==|;|\[)")
_PY_ASSIGN_RE = re.compile(r"^[ \t]*([A-Za-z_]\w*)\s*(?:[-+*/|&]?=)(?!=)", re.M)
_PY_FOR_RE = re.compile(r"^[ \t]*(?:async\s+)?for\s+([A-Za-z_][\w, ]*?)\s+in\b", re.M)
_PY_AS_RE = re.compile(r"\bas\s+([A-Za-z_]\w*)\s*[:,]")

# Protected (non-renamed) spans: strings and comments.
_C_PROTECT = re.compile(r'("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/)', re.S)
_PY_FSTRING = re.compile(
    r'([fF][rR]?(?:"""(?:\\.|[^\\])*?"""|\'\'\'(?:\\.|[^\\])*?\'\'\'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'))'
)
_PY_PROTECT = re.compile(
    r'((?:[rRbBuU]{0,2}(?:"""(?:\\.|[^\\])*?"""|\'\'\'(?:\\.|[^\\])*?\'\'\'|'
    r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'))|#[^\n]*)',
    re.S,
)


# ── helpers ───────────────────────────────────────────────────────────


def _is_python(lang: str) -> bool:
    return lang == "python"


def _line_offset(entry: GroundTruthEntry) -> int:
    try:
        return int(entry.metadata.get("snippet_start_line", 1)) - 1
    except (TypeError, ValueError):
        return 0


def _sink_index(entry: GroundTruthEntry, lines: list[str]) -> int | None:
    """0-based snippet line index to target, or None if no usable line."""
    if entry.sink_line is not None:
        idx = entry.sink_line - 1 - _line_offset(entry)
        if 0 <= idx < len(lines) and lines[idx].strip():
            return idx
    call_re = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s or s.startswith(("#", "//", "/*", "*", "@")):
            continue
        if _is_python(entry.lang) and s.startswith(("def ", "class ", "import ", "from ")):
            continue
        if s.startswith(("#include", "#define")):
            continue
        if s.endswith(("{", ":")):
            continue
        if any(m.group(1) not in _CALL_KEYWORDS for m in call_re.finditer(s)):
            return i
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip():
            return i
    return None


def _split_protected(code: str, protect: re.Pattern[str]) -> list[str]:
    return protect.split(code)  # odd indices are protected spans


def _rename_in_code(code: str, mapping: dict[str, str], lang: str) -> str:
    if not mapping:
        return code
    names = sorted(mapping, key=len, reverse=True)
    word_re = re.compile(r"(?<![\w.])(?<!->)(" + "|".join(map(re.escape, names)) + r")\b")

    def sub_word(m: re.Match[str], text: str) -> str:
        if _is_python(lang):
            before = text[: m.start()].rstrip()
            after = text[m.end() :]
            if before.endswith(("(", ",")) and re.match(r"\s*=(?!=)", after):
                return m.group(0)  # keyword argument
        return mapping[m.group(1)]

    def sub_text(text: str) -> str:
        return word_re.sub(lambda m: sub_word(m, text), text)

    if _is_python(lang):
        out: list[str] = []
        for i, part in enumerate(_split_protected(code, _PY_FSTRING)):
            if i % 2:  # f-string: rename only inside {...}
                out.append(
                    re.sub(r"\{([^{}]*)\}", lambda m: "{" + sub_text(m.group(1)) + "}", part)
                )
            else:
                for j, seg in enumerate(_split_protected(part, _PY_PROTECT)):
                    out.append(seg if j % 2 else sub_text(seg))
        return "".join(out)
    segs = _split_protected(code, _C_PROTECT)
    return "".join(s if i % 2 else sub_text(s) for i, s in enumerate(segs))


def _collect_locals(code: str, lang: str) -> list[str]:
    found: list[str] = []
    if _is_python(lang):
        for m in _PY_ASSIGN_RE.finditer(code):
            found.append(m.group(1))
        for m in _PY_FOR_RE.finditer(code):
            found.extend(n.strip() for n in m.group(1).split(",") if n.strip().isidentifier())
        for m in _PY_AS_RE.finditer(code):
            found.append(m.group(1))
        reserved = _PY_RESERVED
    else:
        stripped = "".join(
            "" if i % 2 else s for i, s in enumerate(_split_protected(code, _C_PROTECT))
        )
        found = [m.group(1) for m in _C_DECL_RE.finditer(stripped)]
        reserved = _C_KEYWORDS
    seen: dict[str, None] = {}
    for n in found:
        if n not in reserved and not n.startswith("__") and len(n) > 1:
            seen[n] = None
    return list(seen)


# ── perturbations: each returns (new_code, new_sink_line, info) or None ──

Result = tuple[str, int | None, dict] | None


def _rename_locals(entry: GroundTruthEntry, rng: random.Random) -> Result:
    if entry.lang not in _C_LANGS and not _is_python(entry.lang):
        return None
    code = entry.code_snippet
    names = _collect_locals(code, entry.lang)
    if not names:
        return None
    used = set(re.findall(r"[A-Za-z_]\w*", code))
    mapping: dict[str, str] = {}
    for n in names:
        while True:
            new = f"v_{rng.getrandbits(24):06x}"
            if new not in used:
                used.add(new)
                break
        mapping[n] = new
    new_code = _rename_in_code(code, mapping, entry.lang)
    if new_code == code:
        return None
    return new_code, entry.sink_line, {"renamed": mapping}


def _misleading_comment(entry: GroundTruthEntry, rng: random.Random) -> Result:
    if entry.lang not in _SLASH_LANGS and not _is_python(entry.lang):
        return None
    lines = entry.code_snippet.split("\n")
    idx = _sink_index(entry, lines)
    # avoid unsafe trailing placement
    while idx is not None and idx >= 0 and lines[idx].rstrip().endswith("\\"):
        idx -= 1
    if idx is None or idx < 0:
        return None
    text = rng.choice(_COMMENT_TEXT)
    marker = "#" if _is_python(entry.lang) else "//"
    lines[idx] = f"{lines[idx].rstrip()}  {marker} {text}"
    return "\n".join(lines), entry.sink_line, {"comment": text, "line_index": idx}


def _sanitizer_wrap(entry: GroundTruthEntry, rng: random.Random) -> Result:
    if entry.lang not in _C_LANGS and not _is_python(entry.lang):
        return None
    py = _is_python(entry.lang)
    lines = entry.code_snippet.split("\n")
    idx = _sink_index(entry, lines)
    if idx is None:
        return None
    fn = _SANITIZER_BY_CWE.get(entry.cwe_id, _DEFAULT_SANITIZER)
    line = lines[idx]
    reserved = _PY_RESERVED if py else _C_KEYWORDS
    new_line = None
    if py:
        m = re.search(r"\{([A-Za-z_]\w*)\}", line)
        if m and m.group(1) not in reserved:
            new_line = f"{line[: m.start()]}{{{fn}({m.group(1)})}}{line[m.end() :]}"
    if new_line is None:
        # first bare identifier argument of a call: f(x, ...) / f(a, x)
        for m in re.finditer(r"[(,]\s*([A-Za-z_]\w*)\s*(?=[,)])", line):
            ident = m.group(1)
            if ident in reserved or ident in _CALL_KEYWORDS:
                continue
            s = m.start(1)
            new_line = f"{line[:s]}{fn}({ident}){line[m.end(1) :]}"
            break
    if new_line is None:
        return None
    lines[idx] = new_line
    define = f"def {fn}(x): return x" if py else f"#define {fn}(x) (x)"
    ins = 0
    pat = re.compile(r"^\s*(?:import|from)\s" if py else r"^\s*#\s*include\b")
    for i, ln in enumerate(lines[:60]):
        if pat.match(ln) and ln.count("(") <= ln.count(")") and not ln.rstrip().endswith("\\"):
            ins = i + 1
    if py and ins == 0 and lines and lines[0].startswith(("#!", "# -*-")):
        ins = 1
    lines.insert(ins, define)
    sink = entry.sink_line
    if sink is not None and ins <= idx:
        sink += 1
    return "\n".join(lines), sink, {"sanitizer": fn, "line_shift": 1}


_PERTURBATIONS: dict[str, Callable[[GroundTruthEntry, random.Random], Result]] = {
    KIND_RENAME: _rename_locals,
    KIND_COMMENT: _misleading_comment,
    KIND_SANITIZER: _sanitizer_wrap,
}


def perturb_entry(entry: GroundTruthEntry, kind: str, seed: int = 0) -> GroundTruthEntry:
    """Return a perturbed copy of ``entry`` with id ``<id>__<kind>``.

    ``metadata['perturbation'] = {kind, seed, original_id, applied, ...}``.
    The label is never changed. Deterministic for a given (entry, kind, seed).
    """
    fn = _PERTURBATIONS.get(kind)
    if fn is None:
        raise ValueError(f"unknown perturbation kind {kind!r}; valid: {list(KINDS)}")
    rng = random.Random(f"{seed}:{entry.id}:{kind}")
    result = fn(entry, rng)
    meta = copy.deepcopy(entry.metadata)
    info: dict = {
        "kind": kind,
        "seed": seed,
        "original_id": entry.id,
        "applied": result is not None,
    }
    if result is None:
        return dataclasses.replace(
            entry, id=f"{entry.id}__{kind}", metadata={**meta, "perturbation": info}
        )
    code, sink, extra = result
    info.update(extra)
    return dataclasses.replace(
        entry,
        id=f"{entry.id}__{kind}",
        code_snippet=code,
        sink_line=sink,
        metadata={**meta, "perturbation": info},
    )
