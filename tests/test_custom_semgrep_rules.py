# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Stage-3 quality gate for custom Semgrep rules.

For each rule under ``config/semgrep-custom/<lang>.yaml`` we expect:

* A ``vuln.<ext>`` sample under ``tests/fixtures/security-rules/<lang>/<rule>/``
  that **must** trigger the rule.
* A ``clean.<ext>`` sample under the same directory that **must not** trigger
  the rule.

If the ``opengrep`` (or ``semgrep``) binary is not installed, the test class is
skipped — no false-positive failures in clean environments. CI must run with
opengrep available.

The fixture set is intentionally tiny; growth is tracked by adding more
``<rule>/`` directories with their ``vuln.*`` + ``clean.*`` pairs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "security-rules"
RULES_DIR = REPO_ROOT / "config" / "semgrep-custom"

# Map our fixture lang dir → the Semgrep custom-rules file
_LANG_TO_RULES_FILE = {
    "php": "php.yaml",
    "javascript": "javascript.yaml",
    "go": "go.yaml",
    "python": "python.yaml",
}


def _opengrep_path() -> str | None:
    for binary in ("opengrep", "semgrep"):
        if shutil.which(binary):
            return binary
    return None


pytestmark = pytest.mark.skipif(
    _opengrep_path() is None,
    reason="opengrep / semgrep not installed — skipping custom-rule fixture tests",
)


def _run_scan(rules_file: Path, target: Path) -> list[dict]:
    """Run opengrep with --json and return parsed results list."""
    binary = _opengrep_path()
    assert binary, "guarded by pytestmark.skipif"
    cmd = [
        binary,
        "scan" if binary == "opengrep" else None,
        "--config", str(rules_file),
        "--json",
        "--no-git-ignore",
        "--quiet",
        str(target),
    ]
    # opengrep silently skips paths under tests/ by default unless we pass
    # this flag to bypass any built-in .semgrepignore patterns. Filter the
    # None token out for semgrep (which doesn't use the `scan` subcommand).
    if binary == "opengrep":
        cmd.insert(2, "--x-ignore-semgrepignore-files")
    cmd = [c for c in cmd if c is not None]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # opengrep returns exit 0 on no findings, 1 on findings — both are fine
    if result.returncode not in (0, 1):
        pytest.fail(
            f"opengrep failed (rc={result.returncode}):\nstdout={result.stdout[:400]}\n"
            f"stderr={result.stderr[:400]}"
        )
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        pytest.fail(f"opengrep JSON parse failed: {exc}\nraw={result.stdout[:400]}")
    return data.get("results", [])


def _collect_fixtures() -> list[tuple[str, str]]:
    """Yield (lang, rule_dir_name) pairs that have both vuln + clean samples."""
    pairs: list[tuple[str, str]] = []
    if not FIXTURES.is_dir():
        return pairs
    for lang_dir in sorted(FIXTURES.iterdir()):
        if not lang_dir.is_dir() or lang_dir.name not in _LANG_TO_RULES_FILE:
            continue
        for rule_dir in sorted(lang_dir.iterdir()):
            if not rule_dir.is_dir():
                continue
            has_vuln = any(rule_dir.glob("vuln.*"))
            has_clean = any(rule_dir.glob("clean.*"))
            if has_vuln and has_clean:
                pairs.append((lang_dir.name, rule_dir.name))
    return pairs


@pytest.mark.parametrize(("lang", "rule_dir"), _collect_fixtures())
def test_vuln_sample_fires(lang: str, rule_dir: str) -> None:
    """The vuln.* sample must produce at least one finding from our rules."""
    rules_file = RULES_DIR / _LANG_TO_RULES_FILE[lang]
    assert rules_file.is_file(), f"missing {rules_file}"
    sample_dir = FIXTURES / lang / rule_dir
    vuln_files = list(sample_dir.glob("vuln.*"))
    assert vuln_files, f"no vuln.* in {sample_dir}"
    results = _run_scan(rules_file, vuln_files[0])
    # At least one finding from a rule that matches our directory name
    matched = [r for r in results if rule_dir.replace("-", ".") in r.get("check_id", "")
               or rule_dir in r.get("check_id", "")]
    assert matched, (
        f"expected at least one finding for {lang}/{rule_dir} on {vuln_files[0].name}, "
        f"got {len(results)} unrelated findings: "
        f"{[r.get('check_id') for r in results]}"
    )


@pytest.mark.parametrize(("lang", "rule_dir"), _collect_fixtures())
def test_clean_sample_does_not_fire(lang: str, rule_dir: str) -> None:
    """The clean.* sample must produce no finding from the matching rule."""
    rules_file = RULES_DIR / _LANG_TO_RULES_FILE[lang]
    sample_dir = FIXTURES / lang / rule_dir
    clean_files = list(sample_dir.glob("clean.*"))
    assert clean_files, f"no clean.* in {sample_dir}"
    results = _run_scan(rules_file, clean_files[0])
    matched = [r for r in results if rule_dir.replace("-", ".") in r.get("check_id", "")
               or rule_dir in r.get("check_id", "")]
    assert not matched, (
        f"unexpected finding for {lang}/{rule_dir} on {clean_files[0].name}: "
        f"{[r.get('check_id') for r in matched]}"
    )


def test_every_custom_rule_has_a_fixture() -> None:
    """Every rule in config/semgrep-custom/*.yaml must have a fixture directory.

    Catches drift where someone adds a rule but forgets the golden samples.
    """
    import yaml as _yaml

    missing: list[tuple[str, str]] = []
    for lang, fname in _LANG_TO_RULES_FILE.items():
        path = RULES_DIR / fname
        if not path.is_file():
            continue
        data = _yaml.safe_load(path.read_text()) or {}
        for rule in data.get("rules", []) or []:
            rule_id = rule.get("id", "")
            # Extract suffix after the last '.' — that's our fixture-dir convention
            suffix = rule_id.rsplit(".", 1)[-1] if "." in rule_id else rule_id
            fixture_dir = FIXTURES / lang / suffix
            if not fixture_dir.is_dir():
                missing.append((rule_id, str(fixture_dir.relative_to(REPO_ROOT))))

    assert not missing, (
        "Rules without golden fixtures:\n  "
        + "\n  ".join(f"{rid} → expected {fdir}" for rid, fdir in missing)
    )
