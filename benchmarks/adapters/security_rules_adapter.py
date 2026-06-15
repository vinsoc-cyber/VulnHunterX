# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the in-repo custom-rule fixtures (Go / PHP / JS / Python).

Source: ``tests/fixtures/security-rules/<lang>/<rule>/{vuln,clean}.<ext>``

These are the project's own SAST rule test fixtures — one directory per custom
rule, holding a vulnerable (``vuln.*``) and a safe (``clean.*``) variant. Using
SAST rule test fixtures as ground truth is a recognized practice (Semgrep
``ruleid:``/``ok:`` annotations, CodeQL ``.expected`` files). This is the
finding-shaped, balanced TP/FP dataset for the Go/PHP/JS languages whose rules
have no public benchmark — and it validates *this repo's* new rules directly.

Labels:
    vuln.<ext>  → LABEL_TP  (rule should fire)
    clean.<ext> → LABEL_FP  (rule must NOT fire — a real false-positive trap)

``rule_id`` is the actual Semgrep custom-rule id (``vulnhunterx.<lp>.<rule>``)
when the rule is found in ``config/semgrep-custom/<lang>.yaml``, else the
CodeQL-style ``<lang>/<rule>``. ``cwe_id`` is read from the Semgrep rule
metadata so the verification engine's CWE-fallback question routing works.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar

import yaml

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_csv_list,
    register_adapter,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES_ROOT = _REPO_ROOT / "tests" / "fixtures" / "security-rules"
_SEMGREP_CUSTOM = _REPO_ROOT / "config" / "semgrep-custom"
_MAX_SNIPPET_CHARS = 8000

# fixture-dir lang → (GroundTruthEntry lang, source-file ext, semgrep id prefix,
# semgrep yaml stem).
_LANG_SPEC: dict[str, tuple[str, str, str, str]] = {
    "go": ("go", ".go", "go", "go"),
    "php": ("php", ".php", "php", "php"),
    "javascript": ("javascript", ".js", "js", "javascript"),
    "python": ("python", ".py", "py", "python"),
}


def _load_semgrep_cwe_map(yaml_stem: str) -> dict[str, str]:
    """Map ``<rule-name>`` → primary CWE from config/semgrep-custom/<stem>.yaml."""
    path = _SEMGREP_CUSTOM / f"{yaml_stem}.yaml"
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        logger.warning("Could not parse %s for CWE metadata", path)
        return {}
    out: dict[str, str] = {}
    for rule in data.get("rules", []):
        rule_id = str(rule.get("id", ""))
        if not rule_id:
            continue
        rule_name = rule_id.rsplit(".", 1)[-1]  # vulnhunterx.go.x -> x
        cwes = (rule.get("metadata") or {}).get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        out[rule_name] = str(cwes[0]) if cwes else ""
    return out


@register_adapter
class SecurityRulesAdapter(DatasetAdapter):
    """Load the in-repo custom-rule vuln/clean fixtures as TP/FP pairs."""

    name = "security-rules"
    langs: ClassVar[tuple[str, ...]] = ("go", "php", "javascript", "python")
    family = "custom"
    option_schema: ClassVar[dict[str, OptionSpec]] = {
        "langs": OptionSpec(
            _to_csv_list,
            default=None,
            help="Comma-separated languages to include (e.g. go,php).",
        ),
    }
    install_url = None  # in-repo; no download
    expected_files = ("go", "php", "javascript", "python")

    def __init__(self, dataset_path: Path) -> None:
        # Prefer the given path if it holds the lang subdirs; else fall back to
        # the canonical in-repo fixtures location.
        p = Path(dataset_path)
        self.root = p if (p / "go").is_dir() or (p / "php").is_dir() else _FIXTURES_ROOT

    def load(
        self,
        limit: int = 0,
        langs: list[str] | None = None,
    ) -> list[GroundTruthEntry]:
        wanted = set(langs) if langs else None
        entries: list[GroundTruthEntry] = []
        for lang_dir in sorted(self.root.iterdir() if self.root.is_dir() else []):
            if not lang_dir.is_dir():
                continue
            spec = _LANG_SPEC.get(lang_dir.name)
            if spec is None:
                continue
            gt_lang, ext, id_prefix, yaml_stem = spec
            if wanted and gt_lang not in wanted and lang_dir.name not in wanted:
                continue
            cwe_map = _load_semgrep_cwe_map(yaml_stem)

            for rule_dir in sorted(lang_dir.iterdir()):
                if not rule_dir.is_dir():
                    continue
                rule_name = rule_dir.name
                if rule_name in cwe_map:
                    rule_id = f"vulnhunterx.{id_prefix}.{rule_name}"
                    cwe_id = cwe_map[rule_name]
                else:
                    rule_id = f"{gt_lang}/{rule_name}"  # CodeQL @id style
                    cwe_id = ""

                for variant, label in (("vuln", LABEL_TP), ("clean", LABEL_FP)):
                    matches = list(rule_dir.glob(f"{variant}{ext}")) or list(
                        rule_dir.glob(f"{variant}.*")
                    )
                    if not matches:
                        continue
                    code_file = matches[0]
                    try:
                        snippet = code_file.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        logger.warning("Cannot read %s; skipping", code_file)
                        continue
                    entries.append(
                        GroundTruthEntry(
                            id=f"secrule-{gt_lang}-{rule_name}-{variant}",
                            source_dataset="security-rules",
                            cwe_id=cwe_id,
                            rule_id=rule_id,
                            file_path=str(code_file.relative_to(self.root)),
                            function_name="",
                            start_line=1,
                            lang=gt_lang,
                            label=label,
                            code_snippet=snippet[:_MAX_SNIPPET_CHARS],
                            metadata={
                                "rule_name": rule_name,
                                "variant": variant,
                            },
                        )
                    )
                    if limit and len(entries) >= limit:
                        logger.info("security-rules: loaded %d entries (limit)", len(entries))
                        return entries

        logger.info(
            "security-rules: loaded %d entries (%d TP, %d FP) from %s",
            len(entries),
            sum(1 for e in entries if e.label == LABEL_TP),
            sum(1 for e in entries if e.label == LABEL_FP),
            self.root,
        )
        return entries
