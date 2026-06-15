# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Audit coverage between guided questions and SAST rule emission.

Produces three outputs under output/audit/:

  coverage_matrix.csv          — one row per (lang, rule_id) guided question with
                                  status flags for CWE-map wiring and (optionally)
                                  CodeQL/Semgrep emission.

  gap_summary.md               — human-readable grouping of gaps by severity.

  missing_cwe_map_entries.yaml — patch fragment to extend
                                  config/rule_categories.yaml::cwe_question_map
                                  so every guided-question rule has at least
                                  one CWE entry routing back to it.

Run:
    python scripts/audit_rule_coverage.py
    python scripts/audit_rule_coverage.py --probe-tools   # also probes installed
                                                          # codeql/semgrep binaries

Exit code is 0 if there are zero gaps, 1 otherwise — suitable for CI gating.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PROMPTS_DIR = ROOT / "config" / "prompts"
CATEGORIES_FILE = ROOT / "config" / "rule_categories.yaml"
OUT_DIR = ROOT / "output" / "audit"


# ── Suffix → CWE inference table ───────────────────────────────────────
# For each guided-question suffix that is NOT yet in cwe_question_map,
# this picks the most appropriate CWE. Entries that collide with an
# existing map (same CWE already routed elsewhere) are marked with
# `collides_with` so the audit can surface them for rule renames.
#
# Sources: NIST CWE Glossary; OWASP cheatsheet for variants.
#
# Format: suffix -> (cwe, note). cwe == None means a rule_id rename is
# required (the natural CWE is already taken by a different suffix).
SUFFIX_CWE: dict[str, tuple[str | None, str]] = {
    # Memory safety (cpp gaps)
    "alloca-in-loop":              ("CWE-674", "Uncontrolled recursion / stack growth"),
    "comparison-always-true":      ("CWE-571", "Expression always true"),
    "dangling-pointer":            ("CWE-825", "Expired pointer dereference"),
    "exception-unsafe":            ("CWE-755", "Improper exception handling / RAII violation"),
    "invalid-pointer-deref":       ("CWE-822", "Untrusted pointer dereference"),
    "null-deref":                  (None,      "Rename to null-pointer-dereference (CWE-476)"),
    "overflow-destination":        (None,      "Rename to overflow-buffer (CWE-119)"),
    "overflowing-snprintf":        (None,      "Rename to overflow-buffer (CWE-119/120)"),
    "overrunning-write":           (None,      "Rename to overflow-buffer (CWE-787)"),
    "signed-overflow":             (None,      "Rename to integer-overflow (CWE-190)"),
    "stack-address-escape":        ("CWE-562", "Return of stack variable address"),
    "type-confusion":              ("CWE-843", "Access of resource using incompatible type"),
    "uncontrolled-allocation-size":("CWE-789", "Uncontrolled memory allocation"),
    "uninitialized-local":         (None,      "Rename to use-of-uninitialized-variable (CWE-457)"),
    "unsafe-functions":            ("CWE-676", "Use of potentially dangerous function"),
    "use-after-move":              ("CWE-672", "Operation on resource after expiration"),

    # Web / HTTP
    "clickjacking":                ("CWE-1021","Improper restriction of rendered UI in frame"),
    "cors-misconfiguration":       ("CWE-942", "Overly permissive cross-origin resource sharing"),
    "missing-origin-check":        (None,      "Variant of CWE-942 — distinct rule_id"),
    "insecure-cookie":             ("CWE-614", "Sensitive cookie without Secure/HttpOnly"),
    "insecure-websocket":          (None,      "Variant of CWE-319 cleartext-transmission"),
    "html-injection":              (None,      "Variant of CWE-79 xss"),
    "dom-clobbering":              (None,      "Variant of CWE-1321 prototype-pollution / CWE-79"),
    "prototype-pollution":         ("CWE-1321","Improperly controlled modification of object prototype"),
    "event-handler-injection":     (None,      "Variant of CWE-79 xss"),
    "open-redirect":               (None,      "Already mapped via CWE-601"),

    # PHP-specific
    "type-juggling":               ("CWE-1025","Comparison using wrong factors"),
    "extract-injection":           ("CWE-1062","Parent class with references to child class"),
    "variable-variables":          ("CWE-621", "Variable extraction"),
    "file-inclusion":              ("CWE-98",  "PHP file inclusion of attacker-controlled file"),
    "stream-wrapper-injection":    (None,      "Variant of CWE-73 path-injection"),

    # JavaScript / Electron
    "electron-node-integration":   ("CWE-1188","Insecure default initialization of resource"),
    "untrusted-module-loading":    ("CWE-470", "Use of externally-controlled input to select class/code"),

    # Authentication / Authorization
    "jndi-injection":              (None,      "Variant of CWE-917 template-injection / log4shell"),
    "log4j-injection":             (None,      "Variant of CWE-117 log-injection / log4shell"),
    "missing-jwt-signature-check": ("CWE-347", "Improper verification of cryptographic signature"),
    "missing-access-control":      (None,      "Variant of CWE-862 missing-authorization"),
    "improper-privilege-management":("CWE-269","Improper privilege management"),
    "spring-actuator-exposed":     ("CWE-250", "Execution with unnecessary privileges (mgmt endpoints)"),
    "hardcoded-credential-in-source":(None,    "Rename to hardcoded-credentials (CWE-798)"),

    # Cryptography variants
    "ecb-encryption":              (None,      "Variant of CWE-327 weak-cryptographic-algorithm"),
    "insecure-tls":                (None,      "Variant of CWE-295 / CWE-326 — distinct rule_id"),
    "insecure-tls-context":        (None,      "Variant of CWE-295 certificate-validation-disabled"),
    "insufficient-key-size":       (None,      "Variant of CWE-326 insecure-tls-version"),

    # Resource management
    "resource-leak":               ("CWE-775", "Missing release of file descriptor / handle"),
    "thread-leak":                 ("CWE-402", "Transmission of private resources to new sphere"),
    "goroutine-leak":              ("CWE-405", "Asymmetric resource consumption"),
    "panic-in-handler":            ("CWE-248", "Uncaught exception"),

    # Concurrency variants
    "async-race-condition":        (None,      "Variant of CWE-362 race-condition"),
    "thread-safety-violation":     ("CWE-366", "Race condition within a thread"),

    # Injection variants
    "command-line-injection":      (None,      "Rename to command-injection (CWE-78)"),
    "format-string-injection":     (None,      "Variant of CWE-134 tainted-format-string"),
    "regex-injection":             (None,      "Variant of CWE-1333 regex-dos"),
    "django-raw-sql":              (None,      "Variant of CWE-89 sql-injection"),
    "unsafe-string-formatting":    (None,      "Variant of CWE-134 tainted-format-string"),
    "unsafe-yaml":                 (None,      "Variant of CWE-502 unsafe-deserialization"),
    "nosql-injection":             ("CWE-943", "NoSQL query injection"),

    # Other
    "incorrect-return-value-check":("CWE-253", "Incorrect check of function return value"),
    "deprecated-api":              ("CWE-477", "Use of obsolete function"),
    "flask-debug":                 ("CWE-489", "Active debug code"),
    "insecure-temporary-file":     ("CWE-377", "Insecure temporary file"),
    "mass-assignment":             ("CWE-915", "Improperly controlled modification of dynamically-determined object attributes"),
    "overly-permissive-file":      ("CWE-275", "Permission issues"),
    "sensitive-data-exposure":     (None,      "Variant of CWE-200 information-exposure"),
    "unsafe-pointer":              ("CWE-704", "Incorrect type conversion or cast (Go unsafe.Pointer)"),
    "xml-bomb":                    ("CWE-776", "Improper restriction of recursive entity references"),
    "zip-slip":                    (None,      "Variant of CWE-22 path-injection"),
    "cgo-vulnerability":           ("CWE-242", "Use of inherently dangerous function (cgo)"),
}


def _parse_guided_rules() -> list[tuple[str, str, str]]:
    """Return list of (lang, rule_id, suffix) for every guided-question rule."""
    rules: list[tuple[str, str, str]] = []
    for f in sorted(PROMPTS_DIR.glob("*_questions.yaml")):
        if f.stem == "default_questions":
            continue
        lang = f.stem.replace("_questions", "")
        data = yaml.safe_load(f.read_text()) or {}
        for rule_id in data:
            suffix = rule_id.split("/", 1)[1] if "/" in rule_id else rule_id
            rules.append((lang, rule_id, suffix))
    return rules


def _load_cwe_map() -> dict[str, str]:
    """Return the cwe → suffix dict from rule_categories.yaml."""
    data = yaml.safe_load(CATEGORIES_FILE.read_text()) or {}
    return dict(data.get("cwe_question_map") or {})


def _probe_codeql_rules() -> dict[str, set[str]]:
    """Return {lang: {rule_id, ...}} for the security-extended suite of each language.

    Requires the `codeql` binary on PATH; returns an empty dict if unavailable.
    """
    if not shutil.which("codeql"):
        return {}
    suites = {
        "cpp":        "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "python":     "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "java":       "codeql/java-queries:codeql-suites/java-security-extended.qls",
        "go":         "codeql/go-queries:codeql-suites/go-security-extended.qls",
        # PHP CodeQL is beta — skip
    }
    out: dict[str, set[str]] = {}
    for lang, suite in suites.items():
        try:
            r = subprocess.run(
                ["codeql", "resolve", "queries", suite, "--format=json"],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode != 0:
                continue
            data = json.loads(r.stdout)
            entries = data if isinstance(data, list) else data.get("queries", [])
            ids = set()
            for entry in entries:
                # `codeql resolve queries --format=json` may return either a list
                # of metadata objects or a bare list of .ql path strings depending
                # on the CLI version. Only objects carry a rule id; skip the rest.
                if not isinstance(entry, dict):
                    continue
                meta = entry.get("metadata") or {}
                rid = meta.get("id") or entry.get("id") or ""
                if rid:
                    ids.add(rid)
            out[lang] = ids
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            continue
    return out


# Packs verified to load against semgrep.dev as of Stage-2 audit.
# Update this list when adding to config/rule_categories.yaml.
_KNOWN_GOOD_PACKS: list[str] = [
    "auto",
    "p/security-audit",
    "p/secrets",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/gitleaks",
    "p/jwt",
    "p/insecure-transport",
    "p/python", "p/django", "p/flask",
    "p/javascript", "p/typescript", "p/nodejs", "p/eslint-plugin-security",
    "p/java",
    "p/php",
    "p/gosec",
]


def _probe_semgrep_rules() -> set[str]:
    """Return set of Semgrep rule IDs from default registry packs.

    Requires the `semgrep` binary on PATH; returns an empty set if unavailable.
    """
    if not shutil.which("semgrep"):
        return set()
    sample_dir = ROOT / "tests" / "fixtures" / "_audit_sample"
    sample_dir.mkdir(parents=True, exist_ok=True)
    sample = sample_dir / "sample.py"
    sample.write_text("x = 1\n")
    try:
        r = subprocess.run(
            ["semgrep", "--config=auto", "--config=p/security-audit",
             "--json", "--quiet", "--dryrun", str(sample_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode not in (0, 1):
            return set()
        data = json.loads(r.stdout or "{}")
        return {res.get("check_id", "") for res in data.get("results", []) if res.get("check_id")}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return set()


def _build_matrix(
    rules: list[tuple[str, str, str]],
    cwe_map: dict[str, str],
    codeql_rules: dict[str, set[str]],
    semgrep_rules: set[str],
) -> list[dict[str, str]]:
    """Build coverage matrix rows."""
    mapped_suffixes = set(cwe_map.values())
    matrix = []
    for lang, rule_id, suffix in rules:
        in_map = suffix in mapped_suffixes
        cwe_for_suffix = next((c for c, s in cwe_map.items() if s == suffix), "")
        codeql_hits = sorted(r for r in codeql_rules.get(lang, set())
                             if r == rule_id or r.endswith("/" + suffix))
        semgrep_hits = sorted(r for r in semgrep_rules
                              if suffix in r.lower())
        # Gap priority — A: already wired; B: not wired but easy add; C: collision/rename needed
        if in_map:
            priority = "A"
        elif suffix in SUFFIX_CWE and SUFFIX_CWE[suffix][0]:
            priority = "B"
        else:
            priority = "C"
        matrix.append({
            "lang": lang,
            "rule_id": rule_id,
            "suffix": suffix,
            "cwe_currently_mapped": cwe_for_suffix,
            "in_cwe_question_map": "yes" if in_map else "no",
            "codeql_match": ";".join(codeql_hits) or "—",
            "semgrep_match": ";".join(semgrep_hits) or "—",
            "gap_priority": priority,
        })
    return matrix


def _emit_csv(matrix: list[dict[str, str]]) -> Path:
    path = OUT_DIR / "coverage_matrix.csv"
    fieldnames = ["lang", "rule_id", "suffix", "cwe_currently_mapped",
                  "in_cwe_question_map", "codeql_match", "semgrep_match",
                  "gap_priority"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(matrix)
    return path


def _emit_gap_summary(matrix: list[dict[str, str]]) -> Path:
    path = OUT_DIR / "gap_summary.md"
    by_priority: dict[str, list[dict]] = defaultdict(list)
    for row in matrix:
        by_priority[row["gap_priority"]].append(row)

    lines = ["# Guided-Question vs SAST Coverage Audit", ""]
    lines.append(f"Total guided-question rules: **{len(matrix)}**")
    for prio in ("A", "B", "C"):
        lines.append(f"- Priority {prio}: **{len(by_priority[prio])}** rules")
    lines.append("")

    titles = {
        "A": "Priority A — already wired (CWE in cwe_question_map)",
        "B": "Priority B — needs CWE map entry (cwe inferable, no collision)",
        "C": "Priority C — needs rule_id rename or distinct custom-rule wiring",
    }
    for prio in ("C", "B", "A"):
        rows = by_priority[prio]
        if not rows:
            continue
        lines.append(f"## {titles[prio]}")
        lines.append("")
        by_lang: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            by_lang[r["lang"]].append(r)
        for lang in sorted(by_lang):
            lines.append(f"### {lang} ({len(by_lang[lang])})")
            for r in sorted(by_lang[lang], key=lambda x: x["rule_id"]):
                note = SUFFIX_CWE.get(r["suffix"], ("", ""))[1]
                cwe_target = SUFFIX_CWE.get(r["suffix"], ("",))[0] or "—"
                extras = []
                if prio != "A":
                    extras.append(f"target_cwe={cwe_target}")
                    if note:
                        extras.append(f"note={note}")
                lines.append(f"- `{r['rule_id']}` " + " ".join(extras))
            lines.append("")
    path.write_text("\n".join(lines))
    return path


def _emit_missing_cwe_patch(matrix: list[dict[str, str]]) -> Path:
    """Emit YAML patch fragment to extend cwe_question_map with B-priority entries."""
    additions: dict[str, str] = {}
    for row in matrix:
        if row["gap_priority"] != "B":
            continue
        cwe, _ = SUFFIX_CWE.get(row["suffix"], (None, ""))
        if cwe:
            additions[cwe] = row["suffix"]

    path = OUT_DIR / "missing_cwe_map_entries.yaml"
    lines = [
        "# Patch fragment for config/rule_categories.yaml::cwe_question_map",
        "# Generated by scripts/audit_rule_coverage.py — review before merging.",
        "# These CWEs route Semgrep/CodeQL findings to language-specific guided questions",
        "# for rules that currently fall back to 'default' / 'generic'.",
        "",
        "cwe_question_map:",
    ]
    for cwe in sorted(additions, key=lambda c: int(c.replace("CWE-", ""))):
        lines.append(f"  {cwe}: \"{additions[cwe]}\"")
    path.write_text("\n".join(lines) + "\n")
    return path


def _verify_known_packs() -> int:
    """Probe each pack in ``_KNOWN_GOOD_PACKS`` to confirm it still loads.

    Tries opengrep first, then semgrep. Returns 0 if all packs load, 1 if any
    404 or otherwise fails.
    """
    tool = "opengrep" if shutil.which("opengrep") else ("semgrep" if shutil.which("semgrep") else None)
    if not tool:
        print("verify-packs: neither opengrep nor semgrep is installed", file=sys.stderr)
        return 1

    sample_dir = ROOT / "tests" / "fixtures" / "_audit_sample"
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "sample.py").write_text("x = 1\n")

    print(f"Verifying {len(_KNOWN_GOOD_PACKS)} registry packs via {tool}…")
    failed: list[tuple[str, str]] = []
    for pack in _KNOWN_GOOD_PACKS:
        try:
            r = subprocess.run(
                [tool, f"--config={pack}", str(sample_dir)],
                capture_output=True, text=True, timeout=60,
            )
            out = (r.stdout or "") + (r.stderr or "")
            if "HTTP 404" in out or "Failed to download" in out:
                failed.append((pack, "404"))
                print(f"  [FAIL] {pack} — 404")
            else:
                # Count loaded rules from the scan banner
                import re
                m = re.search(r"with (\d+) Code rules", out)
                rules = m.group(1) if m else "?"
                print(f"  [ OK ] {pack} ({rules} rules)")
        except subprocess.TimeoutExpired:
            failed.append((pack, "timeout"))
            print(f"  [FAIL] {pack} — timeout")
        except Exception as exc:
            failed.append((pack, str(exc)))
            print(f"  [FAIL] {pack} — {exc}")

    if failed:
        print(f"\n{len(failed)} pack(s) failed verification.", file=sys.stderr)
        return 1
    print(f"\nAll {len(_KNOWN_GOOD_PACKS)} packs verified.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probe-tools", action="store_true",
                   help="Probe installed codeql/semgrep binaries for rule IDs.")
    p.add_argument("--verify-packs", action="store_true",
                   help="Probe each pack in _KNOWN_GOOD_PACKS via semgrep/opengrep "
                        "to confirm it still resolves on the registry. Prints a "
                        "summary and returns non-zero if any 404.")
    p.add_argument("--fail-on-gaps", action="store_true",
                   help="Exit with code 1 if any priority-B or priority-C gaps remain.")
    args = p.parse_args(argv)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.verify_packs:
        return _verify_known_packs()

    rules = _parse_guided_rules()
    cwe_map = _load_cwe_map()
    codeql_rules = _probe_codeql_rules() if args.probe_tools else {}
    semgrep_rules = _probe_semgrep_rules() if args.probe_tools else set()

    matrix = _build_matrix(rules, cwe_map, codeql_rules, semgrep_rules)
    csv_path = _emit_csv(matrix)
    gap_path = _emit_gap_summary(matrix)
    patch_path = _emit_missing_cwe_patch(matrix)

    by_prio: dict[str, int] = defaultdict(int)
    for r in matrix:
        by_prio[r["gap_priority"]] += 1

    print(f"Total guided-question rules: {len(matrix)}")
    print(f"  Priority A (already wired):     {by_prio['A']}")
    print(f"  Priority B (CWE-map gap):       {by_prio['B']}")
    print(f"  Priority C (rename/collision):  {by_prio['C']}")
    print()
    print(f"Matrix:        {csv_path.relative_to(ROOT)}")
    print(f"Gap summary:   {gap_path.relative_to(ROOT)}")
    print(f"CWE patch:     {patch_path.relative_to(ROOT)}")
    if not args.probe_tools:
        print()
        print("Tip: pass --probe-tools to inspect installed codeql/semgrep coverage")

    if args.fail_on_gaps and (by_prio["B"] or by_prio["C"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
