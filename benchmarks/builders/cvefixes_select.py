# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Select CVE fix commits from a CVEfixes SQLite database.

Output is JSONL fix specs consumed by ``benchmarks/scripts/build_revpair_manifest.py``::

    {"cve_id", "cve_published", "repo_url", "lang", "cwe", "fix_sha",
     "parent_sha", "changed_files", "source": "cvefixes"}

CVEfixes (Bhandari et al., PROMISE 2021; https://github.com/secureIT-project/CVEfixes,
Zenodo DOI 10.5281/zenodo.4476563). The schema names used here are centralized
in ``SCHEMA`` below. They follow the CVEfixes collection code (``fixes``,
``commits``, ``file_change``, ``cve``, ``cwe_classification``); verify against
the downloaded DB if a release changes them. The ``commits.parents`` column is
stored as the string repr of a Python list (``"['<sha>']"``); JSON lists and
comma-separated forms are tolerated too.

All database content (URLs, paths, SHAs) is untrusted data: repo URLs are
restricted to https on known forges, and SHAs must be hex.

Selection rules: exactly one distinct fix commit per CVE, exactly one parent,
all changed files in one supported language, at most ``--max-files`` changed
files, the CVE's first CWE (sorted) that the rule packs cover for that
language, optional publication window, then deterministic seeded sampling
with per-language / per-CWE caps.

Usage::

    python -m benchmarks.builders.cvefixes_select --db CVEfixes.db --out fixes.jsonl \\
        --langs python,javascript,php --max-files 3 --per-lang 50 --seed 1
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import random
import re
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from benchmarks.adapters.cwe_rule_map import CWE_TO_RULES

logger = logging.getLogger(__name__)

# Centralized CVEfixes schema names: (table, col, col, ...). Single place to
# fix if a release differs.
SCHEMA = {
    "fixes": ("fixes", "cve_id", "hash", "repo_url"),
    "commits": ("commits", "hash", "repo_url", "parents"),
    "file_change": ("file_change", "hash", "filename", "new_path", "programming_language"),
    "cve": ("cve", "cve_id", "published_date"),
    "cwe_class": ("cwe_classification", "cve_id", "cwe_id"),
}

# CVEfixes programming_language value (lowercased) -> VulnHunterX lang.
LANG_MAP: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "php": "php",
    "go": "go",
    "java": "java",
    "c": "c",
    "c++": "cpp",
    "c#": "csharp",
}
DEFAULT_LANGS = ("python", "javascript", "php")
_LANG_RULE_PREFIX = {
    "python": "py/",
    "javascript": "js/",
    "php": "php/",
    "java": "java/",
    "c": "cpp/",
    "cpp": "cpp/",
}
_ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)

FILTER_ORDER = (
    "single_fix_commit",
    "valid_repo_url",
    "valid_sha",
    "single_parent",
    "published_window",
    "files_le_max",
    "language_match",
    "cwe_covered",
    "per_cap",
)


def cwe_covered(cwe: str, lang: str) -> bool:
    """True if the CWE has a rule-pack mapping applicable to ``lang``."""
    rules = CWE_TO_RULES.get(cwe, [])
    prefix = _LANG_RULE_PREFIX.get(lang)
    if prefix is None:
        return bool(rules)  # go/csharp: no prefix convention; any mapping
    return any(r.startswith(prefix) for r in rules)


def valid_repo_url(url: str) -> bool:
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return False
    return (
        p.scheme == "https"
        and host in _ALLOWED_HOSTS
        and not p.username
        and not p.password
        and len([s for s in p.path.split("/") if s]) >= 2
    )


def parse_parents(raw: object) -> list[str]:
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []
    try:
        val = ast.literal_eval(s)
        if isinstance(val, (list, tuple)):
            return [str(x) for x in val]
    except (ValueError, SyntaxError):
        pass
    return [p for p in re.split(r"[,\s\[\]'\"]+", s) if p]


def normalize_cwe(raw: str) -> str:
    m = _CWE_RE.match((raw or "").strip())
    return f"CWE-{m.group(1)}" if m else ""


def open_ro(db: Path) -> sqlite3.Connection:
    uri = f"file:{Path(db).resolve().as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def select_fixes(
    db: Path,
    langs: Iterable[str] = DEFAULT_LANGS,
    max_files: int = 3,
    published_after: str = "",
    published_before: str = "",
    seed: int = 0,
    per_lang: int = 0,
    per_cwe: int = 0,
) -> tuple[list[dict], Counter]:
    """Return (specs, attrition); attrition counts CVEs dropped per filter."""
    want = list(langs)
    for lg in want:
        if lg not in set(LANG_MAP.values()):
            raise ValueError(f"unsupported language {lg!r}")
    attr: Counter = Counter()
    fx, cm, fc, cv, cc = (
        SCHEMA[k] for k in ("fixes", "commits", "file_change", "cve", "cwe_class")
    )
    conn = open_ro(db)
    try:
        by_cve: dict[str, set[tuple[str, str]]] = {}
        for cve_id, h, repo in conn.execute(
            f"SELECT DISTINCT {fx[1]}, {fx[2]}, {fx[3]} FROM {fx[0]} ORDER BY 1,2,3"
        ):
            by_cve.setdefault(cve_id, set()).add((h, repo))
        attr["total"] = len(by_cve)

        cands: list[dict] = []
        for cve_id in sorted(by_cve):
            fixes = by_cve[cve_id]
            if len(fixes) != 1:
                attr["single_fix_commit"] += 1
                continue
            sha, repo = next(iter(fixes))
            if not valid_repo_url(repo or ""):
                attr["valid_repo_url"] += 1
                continue
            if not _SHA_RE.match(sha or ""):
                attr["valid_sha"] += 1
                continue
            row = conn.execute(
                f"SELECT {cm[3]} FROM {cm[0]} WHERE {cm[1]}=? AND {cm[2]}=?",
                (sha, repo),
            ).fetchone()
            parents = parse_parents(row[0]) if row else []
            if len(parents) != 1 or not _SHA_RE.match(parents[0]):
                attr["single_parent"] += 1
                continue
            prow = conn.execute(
                f"SELECT {cv[2]} FROM {cv[0]} WHERE {cv[1]}=?", (cve_id,)
            ).fetchone()
            pub = str((prow[0] if prow else "") or "")[:10]
            if (published_after and not (pub and pub >= published_after)) or (
                published_before and not (pub and pub <= published_before)
            ):
                attr["published_window"] += 1
                continue
            files = conn.execute(
                f"SELECT {fc[2]}, {fc[3]}, {fc[4]} FROM {fc[0]} WHERE {fc[1]}=? ORDER BY 1",
                (sha,),
            ).fetchall()
            if not files or len(files) > max_files:
                attr["files_le_max"] += 1
                continue
            langset = {LANG_MAP.get(str(pl or "").lower()) for _f, _p, pl in files}
            if len(langset) != 1 or next(iter(langset)) not in want:
                attr["language_match"] += 1
                continue
            lang = next(iter(langset))
            cwe = ""
            for (raw,) in conn.execute(
                f"SELECT {cc[2]} FROM {cc[0]} WHERE {cc[1]}=? ORDER BY 1", (cve_id,)
            ):
                n = normalize_cwe(raw)
                if n and cwe_covered(n, lang):
                    cwe = n
                    break
            if not cwe:
                attr["cwe_covered"] += 1
                continue
            cands.append(
                {
                    "cve_id": cve_id,
                    "cve_published": pub,
                    "repo_url": repo,
                    "lang": lang,
                    "cwe": cwe,
                    "fix_sha": sha,
                    "parent_sha": parents[0],
                    "changed_files": [str(p or f) for f, p, _l in files],
                    "source": "cvefixes",
                }
            )
    finally:
        conn.close()

    random.Random(seed).shuffle(cands)  # cands start sorted -> deterministic per seed
    out: list[dict] = []
    lang_n: Counter = Counter()
    cwe_n: Counter = Counter()
    for c in cands:
        key = (c["lang"], c["cwe"])
        if (per_lang and lang_n[c["lang"]] >= per_lang) or (per_cwe and cwe_n[key] >= per_cwe):
            attr["per_cap"] += 1
            continue
        lang_n[c["lang"]] += 1
        cwe_n[key] += 1
        out.append(c)
    out.sort(key=lambda c: (want.index(c["lang"]), c["cve_id"]))
    return out, attr


def format_attrition(attr: Counter, selected: int) -> str:
    lines = [
        "filter                 dropped",
        f"{'cves_with_fixes':<22} {attr['total']:>7}  (start)",
    ]
    lines += [f"{k:<22} {attr[k]:>7}" for k in FILTER_ORDER]
    lines.append(f"{'selected':<22} {selected:>7}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Select CVEfixes fix commits")
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--langs", default=",".join(DEFAULT_LANGS))
    ap.add_argument("--max-files", type=int, default=3)
    ap.add_argument("--published-after", default="")
    ap.add_argument("--published-before", default="")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--per-lang", type=int, default=0)
    ap.add_argument("--per-cwe", type=int, default=0)
    a = ap.parse_args(argv)
    if not a.db.is_file():
        print(f"error: database not found: {a.db}", file=sys.stderr)
        return 2
    langs = [x.strip() for x in a.langs.split(",") if x.strip()]
    specs, attr = select_fixes(
        a.db,
        langs,
        a.max_files,
        a.published_after,
        a.published_before,
        a.seed,
        a.per_lang,
        a.per_cwe,
    )
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open("w", encoding="utf-8") as fh:
        for s in specs:
            fh.write(json.dumps(s, sort_keys=True) + "\n")
    print(format_attrition(attr, len(specs)))
    print(f"wrote {len(specs)} specs to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
