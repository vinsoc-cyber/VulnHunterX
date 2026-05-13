# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Rule profiles and security category management.

Loads ``config/rule_categories.yaml`` and exposes:

* **RuleProfile** – preset combinations of CodeQL suites and Semgrep/OpenGrep
  configs (``standard`` / ``extended`` / ``maximum``).
* **SecurityCategory** – CWE-based groupings (``injection``, ``xss``, …)
  used to filter which findings to verify.
* **CWE → question mapping** – maps CWE IDs to guided-question rule suffixes
  so Semgrep findings receive language-specific questions instead of the
  generic fallback.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vuln_hunter_x.codeql.analysis import CodeQLAnalyzer

logger = logging.getLogger(__name__)


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RuleProfile:
    """A named preset controlling which rules each SAST tool runs.

    Custom-rule fields (added Stage 1 of the full-coverage plan):

    * ``include_custom_codeql`` – if True, layer ``config/codeql-custom/<lang>/suite.qls``
      on top of the built-in suite during ``codeql database analyze``.
    * ``custom_semgrep_path`` – optional path template (may contain ``${LANG}``)
      pointing to a custom Semgrep ruleset. Appended to ``semgrep_configs`` and
      ``opengrep_configs`` at resolution time in ``cmd_analyze``.
    """

    name: str
    description: str
    codeql_suite_suffix: str
    semgrep_configs: list[str]
    opengrep_configs: list[str]
    include_custom_codeql: bool = False
    custom_semgrep_path: str = ""


@dataclass(frozen=True)
class SecurityCategory:
    """A security-domain grouping defined by CWE IDs."""

    name: str
    description: str
    cwes: frozenset[str]


# ── Manager ──────────────────────────────────────────────────────────────────


@dataclass
class RuleProfileManager:
    """Load and query rule profiles, security categories, and CWE mappings.

    Parameters
    ----------
    config_path:
        Path to ``rule_categories.yaml``.  ``None`` uses built-in defaults.
    """

    _profiles: dict[str, RuleProfile] = field(default_factory=dict, repr=False)
    _categories: dict[str, SecurityCategory] = field(default_factory=dict, repr=False)
    _cwe_question_map: dict[str, str] = field(default_factory=dict, repr=False)

    def __init__(self, config_path: Path | None = None) -> None:
        self._profiles = {}
        self._categories = {}
        self._cwe_question_map = {}

        if config_path and config_path.is_file():
            self._load(config_path)
        else:
            self._load_defaults()

    # ── Loading ──────────────────────────────────────────────────────────

    def _load(self, config_path: Path) -> None:
        try:
            with open(config_path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception:
            logger.warning("Failed to load %s – using built-in defaults", config_path)
            self._load_defaults()
            return

        # Profiles
        for name, cfg in (data.get("profiles") or {}).items():
            if not isinstance(cfg, dict):
                continue
            self._profiles[name] = RuleProfile(
                name=name,
                description=cfg.get("description", ""),
                codeql_suite_suffix=cfg.get("codeql_suite_suffix", "security-extended"),
                semgrep_configs=cfg.get("semgrep_configs", ["auto"]),
                opengrep_configs=cfg.get("opengrep_configs", ["auto"]),
                include_custom_codeql=bool(cfg.get("include_custom_codeql", False)),
                custom_semgrep_path=str(cfg.get("custom_semgrep_path", "")),
            )

        # Categories
        for name, cfg in (data.get("categories") or {}).items():
            if not isinstance(cfg, dict):
                continue
            cwes = cfg.get("cwes") or []
            self._categories[name] = SecurityCategory(
                name=name,
                description=cfg.get("description", ""),
                cwes=frozenset(str(c) for c in cwes),
            )

        # CWE → question suffix map
        raw_map = data.get("cwe_question_map") or {}
        self._cwe_question_map = {str(k): str(v) for k, v in raw_map.items()}

        if not self._profiles:
            self._load_defaults()

    def _load_defaults(self) -> None:
        """Provide sensible built-in defaults when no config file exists."""
        self._profiles["standard"] = RuleProfile(
            name="standard",
            description="Default — security-extended + auto",
            codeql_suite_suffix="security-extended",
            semgrep_configs=["auto"],
            opengrep_configs=["auto"],
        )

    # ── Profiles ─────────────────────────────────────────────────────────

    def get_profile(self, name: str) -> RuleProfile:
        """Return a named profile.  Raises ``ValueError`` if unknown."""
        if name not in self._profiles:
            available = ", ".join(sorted(self._profiles))
            raise ValueError(
                f"Unknown rule profile {name!r}. Available: {available}"
            )
        return self._profiles[name]

    @property
    def profile_names(self) -> list[str]:
        return sorted(self._profiles)

    def get_codeql_suite(self, profile_name: str, lang: str) -> str:
        """Build the full CodeQL suite string for *lang* under *profile_name*."""
        profile = self.get_profile(profile_name)
        return CodeQLAnalyzer.suite_for_language(lang, profile.codeql_suite_suffix)

    def get_codeql_suites(
        self,
        profile_name: str,
        lang: str,
        *,
        custom_root: Path | None = None,
    ) -> list[str]:
        """Build the list of CodeQL suite specifiers for *lang* under *profile_name*.

        Returns ``[built-in]`` for profiles with ``include_custom_codeql=False``,
        and ``[built-in, <custom-root>/<lang>/suite.qls]`` otherwise. ``custom_root``
        defaults to ``config/codeql-custom`` under the project root.
        """
        profile = self.get_profile(profile_name)
        suites = [CodeQLAnalyzer.suite_for_language(lang, profile.codeql_suite_suffix)]
        if profile.include_custom_codeql:
            base = custom_root if custom_root else Path("config/codeql-custom")
            codeql_lang = "cpp" if lang in ("c", "cpp") else lang
            custom_suite = base / codeql_lang / "suite.qls"
            if custom_suite.is_file():
                suites.append(str(custom_suite))
        return suites

    def get_semgrep_configs(self, profile_name: str, *, lang: str = "") -> list[str]:
        """Return Semgrep configs for *profile_name*, with ``${LANG}`` expanded.

        Appends ``custom_semgrep_path`` (template-expanded) if non-empty and the
        resolved file exists.
        """
        profile = self.get_profile(profile_name)
        configs = [c.replace("${LANG}", lang) for c in profile.semgrep_configs]
        if profile.custom_semgrep_path and lang:
            resolved = profile.custom_semgrep_path.replace("${LANG}", lang)
            if Path(resolved).is_file():
                configs.append(resolved)
        return configs

    def get_opengrep_configs(self, profile_name: str, *, lang: str = "") -> list[str]:
        """Return OpenGrep configs for *profile_name*, with ``${LANG}`` expanded."""
        profile = self.get_profile(profile_name)
        configs = [c.replace("${LANG}", lang) for c in profile.opengrep_configs]
        if profile.custom_semgrep_path and lang:
            resolved = profile.custom_semgrep_path.replace("${LANG}", lang)
            if Path(resolved).is_file():
                configs.append(resolved)
        return configs

    # ── Categories ───────────────────────────────────────────────────────

    def list_categories(self) -> dict[str, SecurityCategory]:
        """All loaded security categories keyed by name."""
        return dict(self._categories)

    @property
    def category_names(self) -> list[str]:
        return sorted(self._categories)

    def get_cwes_for_categories(self, names: list[str]) -> set[str]:
        """Return the union of CWE IDs across the requested categories."""
        result: set[str] = set()
        for name in names:
            cat = self._categories.get(name)
            if cat:
                result.update(cat.cwes)
        return result

    def finding_matches_categories(
        self, cwe_ids: list[str], category_names: list[str],
    ) -> bool:
        """Return ``True`` if any of *cwe_ids* belongs to the requested categories."""
        target_cwes = self.get_cwes_for_categories(category_names)
        return bool(target_cwes.intersection(cwe_ids))

    # ── CWE → Question Mapping ──────────────────────────────────────────

    @property
    def cwe_question_map(self) -> dict[str, str]:
        """CWE-ID → guided-question rule suffix (e.g. ``CWE-89`` → ``sql-injection``)."""
        return dict(self._cwe_question_map)

    def get_question_suffix_for_cwe(self, cwe_id: str) -> str | None:
        """Look up the guided-question rule suffix for a CWE ID."""
        return self._cwe_question_map.get(cwe_id)
