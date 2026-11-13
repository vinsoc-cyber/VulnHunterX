# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Audit which evidence-closure family policy owns each scanner rule.

A family policy (``config/policies/*.yaml``) is selected for a finding by a
language gate, then by any shared CWE or a rule-alias glob. A finding that
matches two families fails closed to Needs More Data. Scanner rules often carry
several CWE tags, so a new CWE selector can silently claim rules whose sink
belongs to another family, or collide with an existing one.

This script enumerates every rule the scanners can emit per language, with the
CWE ids the SARIF parser would derive from its tags, and records which family
(if any) the current policy registry selects for it. The result is a checked-in
inventory; ``tests/test_policy_selector_audit.py`` re-resolves every row so a
selector change that moves a rule is an explicit, reviewable diff.

Rule sources:

  opengrep-vendored      config/opengrep-rules/<lang>/**/*.yaml, with the rule id
                         the vendored tree emits (``config.opengrep-rules.<path>.<id>``)
  semgrep-registry       the same rules under the id the semgrep.dev registry
                         packs emit (``<path>.<file>.<id>``)
  semgrep-custom         config/semgrep-custom/<lang>.yaml
  codeql-custom          config/codeql-custom/<lang>/src/*.ql
  codeql-builtin         the installed ``<lang>-security-and-quality`` suite
                         (needs the ``codeql`` binary; see --keep-codeql-builtin)

Only rules with at least one CWE tag, or that a family already owns, are kept.

Run:
    python scripts/audit_policy_selectors.py                # regenerate
    python scripts/audit_policy_selectors.py --check        # exit 1 on drift
    python scripts/audit_policy_selectors.py --keep-codeql-builtin
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vuln_hunter_x.sarif.parser import _normalize_cwe  # noqa: E402
from vuln_hunter_x.verification.policy.loader import (  # noqa: E402
    PolicyOverlapError,
    PolicyRegistry,
    load_policy_registry,
)

OPENGREP_ROOT = ROOT / "config" / "opengrep-rules"
SEMGREP_CUSTOM_ROOT = ROOT / "config" / "semgrep-custom"
CODEQL_CUSTOM_ROOT = ROOT / "config" / "codeql-custom"
INVENTORY_PATH = ROOT / "tests" / "fixtures" / "policy_selector_audit" / "rule_inventory.json"

# Stage languages (cli/main.py _LANG_CHOICES). ``finding.lang`` is one of these.
LANGS = ("c", "cpp", "csharp", "go", "java", "javascript", "php", "python")
# CodeQL analyses C under the cpp pack; PHP has no CodeQL pack.
CODEQL_PACK = {
    "c": "cpp",
    "cpp": "cpp",
    "csharp": "csharp",
    "go": "go",
    "java": "java",
    "javascript": "javascript",
    "python": "python",
}

SRC_OPENGREP = "opengrep-vendored"
SRC_REGISTRY = "semgrep-registry"
SRC_SEMGREP_CUSTOM = "semgrep-custom"
SRC_CODEQL_CUSTOM = "codeql-custom"
SRC_CODEQL_BUILTIN = "codeql-builtin"
REPO_SOURCES = frozenset({SRC_OPENGREP, SRC_REGISTRY, SRC_SEMGREP_CUSTOM, SRC_CODEQL_CUSTOM})

LEGACY = "legacy"
OVERLAP_PREFIX = "OVERLAP:"

_QL_ID_RE = re.compile(r"^\s*\*\s*@id\s+(\S+)", re.MULTILINE)
_QL_TAGS_RE = re.compile(r"^\s*\*\s*@tags\s+(.*?)(?=^\s*\*\s*@|\*/)", re.MULTILINE | re.DOTALL)

try:
    _YamlLoader: type = yaml.CSafeLoader
except AttributeError:  # pragma: no cover - libyaml not built
    _YamlLoader = yaml.SafeLoader


@dataclass(frozen=True, order=True)
class RuleRow:
    lang: str
    source: str
    rule_id: str
    cwes: tuple[str, ...]
    owner: str = LEGACY


def _cwes_from_tags(tags: Iterable[object]) -> tuple[str, ...]:
    """CWE ids exactly as ``sarif/parser.py`` derives them from rule tags."""
    found = {_normalize_cwe(t) for t in tags if isinstance(t, str)}
    return tuple(sorted((c for c in found if c), key=lambda c: int(c.split("-")[1])))


def _semgrep_rules(path: Path) -> Iterator[tuple[str, tuple[str, ...]]]:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_YamlLoader)  # noqa: S506
    except (yaml.YAMLError, UnicodeDecodeError):
        return
    if not isinstance(data, dict):
        return
    for rule in data.get("rules") or []:
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        cwe = (rule.get("metadata") or {}).get("cwe") or []
        yield str(rule["id"]), _cwes_from_tags([cwe] if isinstance(cwe, str) else cwe)


def _opengrep_rows(lang: str) -> Iterator[RuleRow]:
    lang_dir = OPENGREP_ROOT / lang
    if not lang_dir.is_dir():
        return
    files = sorted(p for p in lang_dir.rglob("*") if p.suffix in {".yaml", ".yml"})
    for path in files:
        if ".test." in path.name:
            continue
        rel = path.relative_to(OPENGREP_ROOT)
        dirs = ".".join(rel.parent.parts)
        for rule_id, cwes in _semgrep_rules(path):
            yield RuleRow(lang, SRC_OPENGREP, f"config.opengrep-rules.{dirs}.{rule_id}", cwes)
            yield RuleRow(lang, SRC_REGISTRY, f"{dirs}.{path.stem}.{rule_id}", cwes)


def _semgrep_custom_rows(lang: str) -> Iterator[RuleRow]:
    path = SEMGREP_CUSTOM_ROOT / f"{lang}.yaml"
    if path.is_file():
        for rule_id, cwes in _semgrep_rules(path):
            yield RuleRow(lang, SRC_SEMGREP_CUSTOM, rule_id, cwes)


def _ql_metadata(path: Path) -> tuple[str, tuple[str, ...]] | None:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8000]
    except OSError:
        return None
    rule_id = _QL_ID_RE.search(head)
    if not rule_id:
        return None
    tags = _QL_TAGS_RE.search(head)
    tokens = re.findall(r"[\w./-]+", tags.group(1)) if tags else []
    return rule_id.group(1), _cwes_from_tags(tokens)


def _codeql_custom_rows(lang: str) -> Iterator[RuleRow]:
    src = CODEQL_CUSTOM_ROOT / CODEQL_PACK.get(lang, lang) / "src"
    if lang not in CODEQL_PACK or not src.is_dir():
        return
    for path in sorted(src.rglob("*.ql")):
        meta = _ql_metadata(path)
        if meta:
            yield RuleRow(lang, SRC_CODEQL_CUSTOM, meta[0], meta[1])


def _codeql_builtin_rows(lang: str, codeql: str) -> Iterator[RuleRow]:
    pack = CODEQL_PACK.get(lang)
    if not pack:
        return
    suite = f"codeql/{pack}-queries:codeql-suites/{pack}-security-and-quality.qls"
    proc = subprocess.run(  # noqa: S603 - fixed argv, read-only query resolution
        [codeql, "resolve", "queries", suite],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"codeql resolve queries failed for {suite}: {proc.stderr.strip()}")
    for line in sorted(proc.stdout.splitlines()):
        meta = _ql_metadata(Path(line.strip()))
        if meta:
            yield RuleRow(lang, SRC_CODEQL_BUILTIN, meta[0], meta[1])


def resolve_owner(registry: PolicyRegistry, row: RuleRow) -> str:
    """Family that owns *row*, ``legacy`` if none, ``OVERLAP:a,b`` if several."""
    try:
        policy = registry.resolve_family(cwe_ids=row.cwes, rule_id=row.rule_id, lang=row.lang)
    except PolicyOverlapError:
        names = sorted(
            p.family
            for p in registry._policies  # noqa: SLF001 - audit needs the member list
            if registry._matches(p, set(row.cwes), row.rule_id, row.lang)  # noqa: SLF001
        )
        return OVERLAP_PREFIX + ",".join(names)
    return policy.family if policy else LEGACY


def _finalize(rows: Iterable[RuleRow], registry: PolicyRegistry) -> list[RuleRow]:
    out: set[RuleRow] = set()
    for row in rows:
        owner = resolve_owner(registry, row)
        if row.cwes or owner != LEGACY:
            out.add(RuleRow(row.lang, row.source, row.rule_id, row.cwes, owner))
    return sorted(out)


def collect_repo_rows(registry: PolicyRegistry | None = None) -> list[RuleRow]:
    """Rows from rule sources stored in this repository (no external tools)."""
    registry = registry or load_policy_registry()
    rows: list[RuleRow] = []
    for lang in LANGS:
        rows.extend(_opengrep_rows(lang))
        rows.extend(_semgrep_custom_rows(lang))
        rows.extend(_codeql_custom_rows(lang))
    return _finalize(rows, registry)


def collect_codeql_builtin_rows(
    codeql: str, registry: PolicyRegistry | None = None
) -> list[RuleRow]:
    registry = registry or load_policy_registry()
    rows: list[RuleRow] = []
    for lang in LANGS:
        rows.extend(_codeql_builtin_rows(lang, codeql))
    return _finalize(rows, registry)


def load_inventory(path: Path = INVENTORY_PATH) -> list[RuleRow]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        RuleRow(r["lang"], r["source"], r["rule_id"], tuple(r["cwes"]), r["owner"])
        for r in data["rules"]
    ]


def render_inventory(rows: list[RuleRow], codeql_version: str) -> str:
    """One rule per line so ownership changes read as single-line diffs."""
    lines = [json.dumps({**asdict(r), "cwes": list(r.cwes)}, sort_keys=True) for r in sorted(rows)]
    header = json.dumps({"codeql_builtin_version": codeql_version})[1:-1]
    return "{\n" + header + ',\n"rules": [\n' + ",\n".join(lines) + "\n]\n}\n"


def _codeql_version(codeql: str) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [codeql, "version", "--format=terse"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def _summary(rows: list[RuleRow]) -> str:
    owned = Counter((r.owner, r.lang) for r in rows if r.owner != LEGACY)
    out = [f"{len(rows)} rules with a CWE tag or a family owner"]
    for (owner, lang), n in sorted(owned.items()):
        out.append(f"  {owner:<40} {lang:<11} {n}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the inventory is stale")
    parser.add_argument(
        "--keep-codeql-builtin",
        action="store_true",
        help="reuse the codeql-builtin rule list already in the inventory (no codeql binary needed)",
    )
    parser.add_argument("--codeql", default="codeql", help="codeql binary (default: from PATH)")
    args = parser.parse_args(argv)

    registry = load_policy_registry()
    rows = collect_repo_rows(registry)

    if args.keep_codeql_builtin:
        previous = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        version = previous.get("codeql_builtin_version", "unknown")
        kept = [r for r in load_inventory() if r.source == SRC_CODEQL_BUILTIN]
        rows += _finalize(kept, registry)
    else:
        codeql = shutil.which(args.codeql)
        if not codeql:
            print("codeql binary not found; pass --keep-codeql-builtin", file=sys.stderr)
            return 2
        version = _codeql_version(codeql)
        rows += collect_codeql_builtin_rows(codeql, registry)

    rendered = render_inventory(rows, version)
    overlaps = [r for r in rows if r.owner.startswith(OVERLAP_PREFIX)]
    for row in overlaps:
        print(f"OVERLAP {row.lang} {row.rule_id} {list(row.cwes)} -> {row.owner}", file=sys.stderr)

    if args.check:
        current = INVENTORY_PATH.read_text(encoding="utf-8") if INVENTORY_PATH.is_file() else ""
        if current != rendered:
            print(
                f"{INVENTORY_PATH.relative_to(ROOT)} is stale; re-run this script", file=sys.stderr
            )
            return 1
        return 0

    INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY_PATH.write_text(rendered, encoding="utf-8")
    print(_summary(rows))
    print(f"wrote {INVENTORY_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
