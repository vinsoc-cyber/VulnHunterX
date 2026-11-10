# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Label-leak redaction for benchmark ground-truth entries.

Some synthetic suites (Juliet, SecLLMHolmes, ...) encode the ground-truth label
in the very text the verifier sees: ``/* FLAW: ... */`` comments, ``bad()`` /
``good()`` function names, CWE-numbered file names, ``p_``/``n_`` file prefixes.
A model can score well by reading those hints instead of analysing the code.

``redact_entry`` returns a *copy* of an entry with that text neutralised while
preserving the number of source lines, so ``sink_line`` stays valid. Original
values are kept under ``metadata["redaction"]`` (never under ``metadata["message"]``,
the only metadata key forwarded to the verifier prompt by ``entry_to_finding``).

Redaction must run AFTER scanner anchoring: anchoring locates the file on disk via
``entry.file_path`` and the anchored line survives because comment blanking keeps
every newline.

Dataset -> rule mapping is extensible via ``register_redaction_rules`` so that
further adapters (for example ``castle`` or ``juliet-java``) can opt in. Datasets
without registered rules are returned untouched.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

from benchmarks.adapters.ground_truth import GroundTruthEntry

# --- patterns -----------------------------------------------------------------

_LABEL_COMMENT_KEYWORD = r"(?:POTENTIAL\s+)?(?:FLAW|FIX|INCIDENTAL)"
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_LABEL_RE = re.compile(r"//[ \t]*" + _LABEL_COMMENT_KEYWORD + r"\b[^\n]*")
_BLOCK_LABEL_RE = re.compile(r"^/\*[\s*]*" + _LABEL_COMMENT_KEYWORD + r"\b")
# Juliet file headers carry the CWE name, variant and sink/source description.
_HEADER_HINT_RE = re.compile(
    r"@description|Label Definition File|Template File|\bSinks?:|\bSource:|"
    r"GoodSink|BadSink|Flow Variant|\bBad\b|\bGood\b|\bFLAW\b|\bFIX\b"
)
_CWE_TOKEN_RE = re.compile(r"CWE[-_ ]?\d+", re.IGNORECASE)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_IDENT_PART_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_LABEL_PARTS = frozenset({"bad", "good"})
_PN_PREFIX_RE = re.compile(r"(?:^|[/\\])[pn]_\d")
_NEUTRAL_FUNC = "target_fn"
_RESIDUAL_WORD_RE = re.compile(r"\b(?:FLAW|FIX)\b")


@dataclass(frozen=True)
class RedactionRules:
    """Which redactions apply to a dataset."""

    blank_label_comments: bool = True
    blank_header_comments: bool = False
    rename_label_identifiers: bool = False
    neutralize_cwe_tokens: bool = True
    anonymize_path: bool = True


_RULES: dict[str, RedactionRules] = {
    "juliet": RedactionRules(blank_header_comments=True, rename_label_identifiers=True),
    "juliet-java": RedactionRules(blank_header_comments=True, rename_label_identifiers=True),
    "secllmholmes": RedactionRules(rename_label_identifiers=True),
    "castle": RedactionRules(blank_header_comments=True, rename_label_identifiers=True),
}


def register_redaction_rules(dataset: str, rules: RedactionRules) -> None:
    """Opt a dataset in to redaction (or override its rules)."""
    _RULES[dataset] = rules


def rules_for(dataset: str) -> RedactionRules | None:
    return _RULES.get(dataset)


def has_redaction_rules(dataset: str) -> bool:
    return dataset in _RULES


# --- helpers ------------------------------------------------------------------


def _blank_block(match: re.Match[str]) -> str:
    """Replace a block comment with an empty one holding the same newlines."""
    return "/*" + "\n" * match.group(0).count("\n") + "*/"


def _blank_comments(code: str, rules: RedactionRules) -> str:
    def _sub(m: re.Match[str]) -> str:
        text = m.group(0)
        if (rules.blank_label_comments and _BLOCK_LABEL_RE.match(text)) or (
            rules.blank_header_comments and _HEADER_HINT_RE.search(text)
        ):
            return _blank_block(m)
        return text

    code = _BLOCK_COMMENT_RE.sub(_sub, code)
    if rules.blank_label_comments:
        code = _LINE_COMMENT_LABEL_RE.sub("//", code)
    return code


def _is_label_identifier(tok: str) -> bool:
    if _CWE_TOKEN_RE.search(tok):
        return True
    parts = [p.lower() for p in _IDENT_PART_RE.findall(tok)]
    return any(p in _LABEL_PARTS for p in parts)


def _neutral(entry_id: str, token: str, prefix: str = "fn") -> str:
    digest = hashlib.sha256(f"{entry_id}\0{token}".encode()).hexdigest()[:6]
    return f"{prefix}_{digest}"


def _rename_identifiers(text: str, entry_id: str) -> str:
    def _sub(m: re.Match[str]) -> str:
        tok = m.group(0)
        return _neutral(entry_id, tok) if _is_label_identifier(tok) else tok

    return _IDENT_RE.sub(_sub, text)


def _neutralize_cwe(text: str) -> str:
    return _CWE_TOKEN_RE.sub("CASE", text)


def _anonymous_path(entry_id: str, file_path: str) -> str:
    ext = posixpath.splitext(file_path.replace("\\", "/"))[1]
    return f"src/{_neutral(entry_id, file_path, 'case')}{ext}"


def _residual_tokens(entry: GroundTruthEntry, rules: RedactionRules) -> list[str]:
    found: set[str] = set()
    for text in (entry.code_snippet, entry.file_path, entry.function_name):
        for m in _RESIDUAL_WORD_RE.finditer(text):
            found.add(m.group(0))
        if rules.neutralize_cwe_tokens:
            for m in _CWE_TOKEN_RE.finditer(text):
                found.add(m.group(0))
        if rules.rename_label_identifiers:
            for m in _IDENT_RE.finditer(text):
                if _is_label_identifier(m.group(0)):
                    found.add(m.group(0))
    if _PN_PREFIX_RE.search(entry.file_path):
        found.add("p_/n_ prefix")
    return sorted(found)


# --- public API ---------------------------------------------------------------


def redact_entry(entry: GroundTruthEntry, dataset: str | None = None) -> GroundTruthEntry:
    """Return a label-leak-redacted copy of ``entry`` (the input is not mutated).

    ``dataset`` defaults to ``entry.source_dataset``. Entries of datasets with no
    registered rules, and already-redacted entries, are returned unchanged.
    """
    rules = _RULES.get(dataset or entry.source_dataset)
    if rules is None or (entry.metadata.get("redaction") or {}).get("applied"):
        return entry

    code = _blank_comments(entry.code_snippet, rules)
    func = entry.function_name
    if rules.rename_label_identifiers:
        code = _rename_identifiers(code, entry.id)
        # The dataset's function_name ("bad()"/"good()") rarely equals a real identifier
        # in the snippet, so map any label-bearing name to one constant neutral name
        # rather than a per-token hash (which would differ between TP and FP entries).
        func = _IDENT_RE.sub(
            lambda m: _NEUTRAL_FUNC if _is_label_identifier(m.group(0)) else m.group(0), func
        )
    if rules.neutralize_cwe_tokens:
        code = _neutralize_cwe(code)
        func = _neutralize_cwe(func)

    file_path = entry.file_path
    if rules.anonymize_path and file_path:
        file_path = _anonymous_path(entry.id, file_path)

    metadata: dict[str, Any] = dict(entry.metadata)
    stashed: dict[str, Any] = {}
    for key in ("cwe_dir", "filename", "variant"):
        if key in metadata:
            stashed[key] = metadata.pop(key)
    if "filename" in stashed and file_path:
        metadata["filename"] = posixpath.basename(file_path)

    redacted = replace(
        entry,
        file_path=file_path,
        function_name=func,
        code_snippet=code,
        metadata=metadata,
    )
    metadata["redaction"] = {
        "applied": True,
        "original_file_path": entry.file_path,
        "original_function_name": entry.function_name,
        "original_metadata": stashed,
        "residual_tokens": _residual_tokens(redacted, rules),
    }
    return redacted


def redact_entries(
    entries: Iterable[GroundTruthEntry], dataset: str | None = None
) -> list[GroundTruthEntry]:
    """Apply :func:`redact_entry` to every entry."""
    return [redact_entry(e, dataset) for e in entries]
