# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Guided questions loading and management."""

from __future__ import annotations

from pathlib import Path

import yaml

from vuln_hunter_x.core.types import GuidedQuestions

# Language name → guided-question prefix used in *_questions.yaml rule IDs.
_LANG_TO_QUESTION_PREFIX: dict[str, str] = {
    "c": "cpp",
    "cpp": "cpp",
    "python": "py",
    "javascript": "js",
    "java": "java",
    "php": "php",
    "go": "go",
    "csharp": "cs",
}

# CWE classes that benefit from a forced second iteration before
# committing to a TP/FP verdict. Each entry maps CWE id to
# (min_iterations, langs) where ``langs`` is a frozenset of languages the
# override applies to. An empty frozenset means "all languages".
#
# Provenance:
#   * Access-control block (CWE-200..863): added 2026-05-15 after the
#     diversevul benchmark showed 100% FN on 1-iter CWE-264 verdicts.
#     Language-agnostic: missing-auth bugs look the same in any language.
#   * Taint-tracking block (CWE-22..1333): added 2026-05-19 after the
#     OWASP-python benchmark showed 1-iter/High accuracy = 57.1% vs
#     2-iter/High = 95.8% on CWE-22/CWE-643. The framework-defense FP
#     traps (apostrophe guards, parameterised XPath, secure_filename,
#     map/list reassignments) live in Python/JS/Java/PHP/Go web code.
#     C-side findings do not have these defenses, and the existing
#     diversevul CWE-264 results pass — so the taint block is gated to
#     framework languages to avoid adding cost on C without benefit.
_FRAMEWORK_LANGS: frozenset[str] = frozenset({
    "python", "javascript", "java", "php", "go", "csharp",
})

_CWE_MIN_ITERATIONS_OVERRIDE: dict[str, tuple[int, frozenset[str]]] = {
    # ── Access control / authorization (all languages) ──
    "CWE-200": (2, frozenset()),  # Information exposure
    "CWE-264": (2, frozenset()),  # Permissions, privileges, and access controls
    "CWE-269": (2, frozenset()),  # Improper privilege management
    "CWE-285": (2, frozenset()),  # Improper authorization
    "CWE-287": (2, frozenset()),  # Improper authentication
    "CWE-306": (2, frozenset()),  # Missing authentication for critical function
    "CWE-862": (2, frozenset()),  # Missing authorization
    "CWE-863": (2, frozenset()),  # Incorrect authorization

    # ── Taint-tracking (framework languages only) ──
    "CWE-22":   (2, _FRAMEWORK_LANGS),   # Path traversal
    "CWE-77":   (2, _FRAMEWORK_LANGS),   # Command injection (generic)
    "CWE-78":   (2, _FRAMEWORK_LANGS),   # OS command injection
    "CWE-79":   (2, _FRAMEWORK_LANGS),   # Cross-site scripting
    "CWE-80":   (2, _FRAMEWORK_LANGS),   # Basic XSS
    "CWE-87":   (2, _FRAMEWORK_LANGS),   # Alternate XSS syntax
    "CWE-89":   (2, _FRAMEWORK_LANGS),   # SQL injection
    "CWE-90":   (2, _FRAMEWORK_LANGS),   # LDAP injection
    "CWE-94":   (2, _FRAMEWORK_LANGS),   # Code injection
    "CWE-95":   (2, _FRAMEWORK_LANGS),   # Eval injection
    "CWE-113":  (2, _FRAMEWORK_LANGS),   # HTTP header injection
    "CWE-134":  (2, _FRAMEWORK_LANGS),   # Uncontrolled format string
    "CWE-501":  (2, _FRAMEWORK_LANGS),   # Trust boundary violation
    "CWE-502":  (2, _FRAMEWORK_LANGS),   # Deserialisation of untrusted data
    "CWE-601":  (2, _FRAMEWORK_LANGS),   # URL redirection to untrusted site (open redirect)
    "CWE-611":  (2, _FRAMEWORK_LANGS),   # XML external entity (XXE)
    "CWE-643":  (2, _FRAMEWORK_LANGS),   # XPath injection
    "CWE-917":  (2, _FRAMEWORK_LANGS),   # Expression/template injection (SSTI)
    "CWE-918":  (2, _FRAMEWORK_LANGS),   # SSRF
    "CWE-1333": (2, _FRAMEWORK_LANGS),   # Inefficient regular expression (ReDoS)
}


class QuestionsLoader:
    """Loads and retrieves guided questions for CodeQL rules."""

    def __init__(self, prompts_dir: Path | None = None):
        self.questions: dict[str, GuidedQuestions] = {}
        self._default_questions: GuidedQuestions | None = None
        self._cwe_question_map: dict[str, str] = {}

        if prompts_dir:
            self.load_from_directory(prompts_dir)

    def set_cwe_question_map(self, cwe_map: dict[str, str]) -> None:
        """Set the CWE-ID → question-rule-suffix mapping for Semgrep matching."""
        self._cwe_question_map = dict(cwe_map)

    def load_from_directory(self, prompts_dir: Path) -> int:
        """
        Load guided questions from all *_questions.yaml files in a directory.

        Files are loaded in sorted (alphabetical) order so the load sequence
        is deterministic.  Each file is merged into the shared questions dict;
        later files override earlier ones if the same rule_id appears twice.

        Args:
            prompts_dir: Directory containing *_questions.yaml files

        Returns:
            Total number of question templates loaded across all files
        """
        count = 0
        for yaml_file in sorted(prompts_dir.glob("*_questions.yaml")):
            count += self.load_from_file(yaml_file)
        return count

    def load_from_file(self, yaml_path: Path) -> int:
        """
        Load guided questions from a YAML file.

        Args:
            yaml_path: Path to the YAML file

        Returns:
            Number of question templates loaded
        """
        if not yaml_path.is_file():
            return 0

        try:
            with open(yaml_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            return 0

        if not isinstance(data, dict):
            return 0

        count = 0
        for rule_id, config in data.items():
            if not isinstance(config, dict):
                continue

            questions = GuidedQuestions(
                rule_id=rule_id,
                short_description=config.get("short_description", ""),
                questions=config.get("questions", []),
                context_hint=config.get("context_hint", ""),
                additional_context=config.get("additional_context", []),
                min_iterations=int(config.get("min_iterations", 1) or 1),
                snippet_window_lines=(
                    int(config["snippet_window_lines"])
                    if config.get("snippet_window_lines")
                    else None
                ),
            )

            if rule_id == "default":
                self._default_questions = questions
            else:
                self.questions[rule_id] = questions

            count += 1

        return count

    def get_questions(
        self,
        rule_id: str,
        *,
        cwe_ids: list[str] | None = None,
        lang: str = "",
    ) -> GuidedQuestions:
        """
        Get guided questions for a rule, with fallback to default.

        Args:
            rule_id: The rule ID (e.g., "cpp/use-after-free")
            cwe_ids: Optional CWE IDs from the finding (used for CWE-based fallback)
            lang: Optional language hint (e.g., "python") for CWE matching

        Returns:
            GuidedQuestions for the rule
        """
        questions, _ = self.get_questions_with_match_info(
            rule_id, cwe_ids=cwe_ids, lang=lang,
        )
        return questions

    def get_questions_with_match_info(
        self,
        rule_id: str,
        *,
        cwe_ids: list[str] | None = None,
        lang: str = "",
    ) -> tuple[GuidedQuestions, str]:
        """
        Get guided questions for a rule and the match type used to find them.

        Match types (in order of preference):
          "exact"      — direct key lookup
          "normalized" — hyphens replaced with slashes
          "prefix"     — bidirectional prefix match
          "lang_prefix"— same language prefix, partial rule-name match
          "cwe"        — matched via CWE ID → question suffix mapping
          "default"    — fell back to default_questions.yaml
          "generic"    — programmatically generated fallback

        Args:
            rule_id: The rule ID (e.g., "cpp/use-after-free" or Semgrep ID)
            cwe_ids: Optional CWE IDs from the finding's SARIF metadata
            lang: Optional language hint (e.g., "python") for CWE matching

        Returns:
            (GuidedQuestions, match_type_str)
        """
        # Resolve the question + match-type, then apply any CWE-class
        # min_iterations override before returning.
        questions, match = self._resolve_questions(rule_id, cwe_ids=cwe_ids, lang=lang)
        questions = self._apply_cwe_min_iterations_override(questions, cwe_ids, lang)
        return questions, match

    def _apply_cwe_min_iterations_override(
        self,
        questions: GuidedQuestions,
        cwe_ids: list[str] | None,
        lang: str = "",
    ) -> GuidedQuestions:
        """Raise ``questions.min_iterations`` if any of the finding's CWEs
        triggers a language-gated override in ``_CWE_MIN_ITERATIONS_OVERRIDE``.

        Each map value is ``(min_iters, langs)`` where ``langs`` is a
        frozenset of languages the override applies to (empty = all).
        No-op when no override applies or when the matched questions
        already declare an equal-or-higher ``min_iterations``.
        """
        if not cwe_ids:
            return questions
        override = 0
        for cwe in cwe_ids:
            entry = _CWE_MIN_ITERATIONS_OVERRIDE.get(cwe)
            if entry is None:
                continue
            min_iters, scope_langs = entry
            if scope_langs and lang and lang not in scope_langs:
                continue
            if min_iters > override:
                override = min_iters
        if override <= questions.min_iterations:
            return questions
        return GuidedQuestions(
            rule_id=questions.rule_id,
            short_description=questions.short_description,
            questions=questions.questions,
            context_hint=questions.context_hint,
            additional_context=questions.additional_context,
            min_iterations=override,
            snippet_window_lines=questions.snippet_window_lines,
        )

    def _resolve_questions(
        self,
        rule_id: str,
        *,
        cwe_ids: list[str] | None = None,
        lang: str = "",
    ) -> tuple[GuidedQuestions, str]:
        # Try exact match
        if rule_id in self.questions:
            return self.questions[rule_id], "exact"

        # Try normalized (replace - with /)
        normalized = rule_id.replace("-", "/")
        if normalized in self.questions:
            return self.questions[normalized], "normalized"

        # Try prefix match (e.g., "cpp/sql-injection" matches "cpp/sql")
        for key in self.questions:
            if rule_id.startswith(key) or key.startswith(rule_id):
                return self.questions[key], "prefix"

        # Try language prefix match
        parts = rule_id.split("/")
        if len(parts) >= 2:
            lang_part = parts[0]
            rule_name = "/".join(parts[1:])

            # Try to find similar rule in same language
            for key, q in self.questions.items():
                if key.startswith(f"{lang_part}/") and rule_name in key:
                    return q, "lang_prefix"

        # Try CWE-based match (for Semgrep/OpenGrep findings with CWE tags)
        if cwe_ids and self._cwe_question_map:
            result = self._match_by_cwe(rule_id, cwe_ids, lang)
            if result:
                return result

        # Return default or generate generic questions
        if self._default_questions:
            return GuidedQuestions(
                rule_id=rule_id,
                short_description=self._default_questions.short_description,
                questions=self._default_questions.questions,
                context_hint=self._default_questions.context_hint,
                additional_context=self._default_questions.additional_context,
                min_iterations=self._default_questions.min_iterations,
                snippet_window_lines=self._default_questions.snippet_window_lines,
            ), "default"

        return self._generate_generic_questions(rule_id), "generic"

    def _match_by_cwe(
        self,
        rule_id: str,
        cwe_ids: list[str],
        lang: str,
    ) -> tuple[GuidedQuestions, str] | None:
        """Try to find guided questions via CWE-ID → question suffix mapping."""
        # Resolve language prefix from the explicit lang hint
        lang_prefix = _LANG_TO_QUESTION_PREFIX.get(lang, "")

        # Fallback: try extracting language from Semgrep-style rule ID
        # (e.g., "python.django.security.injection.sql.raw-query" → "python" → "py")
        if not lang_prefix and "." in rule_id:
            first_segment = rule_id.split(".")[0]
            lang_prefix = _LANG_TO_QUESTION_PREFIX.get(first_segment, "")

        for cwe_id in cwe_ids:
            suffix = self._cwe_question_map.get(cwe_id)
            if not suffix:
                continue

            # Try language-specific match first
            if lang_prefix:
                candidate = f"{lang_prefix}/{suffix}"
                if candidate in self.questions:
                    return self.questions[candidate], "cwe"

            # Fallback: match any language with the right suffix
            for key, q in self.questions.items():
                if key.endswith(f"/{suffix}"):
                    return GuidedQuestions(
                        rule_id=rule_id,
                        short_description=q.short_description,
                        questions=q.questions,
                        context_hint=q.context_hint,
                        additional_context=q.additional_context,
                        min_iterations=q.min_iterations,
                        snippet_window_lines=q.snippet_window_lines,
                    ), "cwe"

        return None
    
    def _generate_generic_questions(self, rule_id: str) -> GuidedQuestions:
        """Generate generic questions for unknown rules."""
        return GuidedQuestions(
            rule_id=rule_id,
            short_description=f"CodeQL finding: {rule_id}",
            questions=[
                "Step 1: Where does the potentially DANGEROUS data originate — what is the ultimate SOURCE (user input, file, network, database)?",
                "Step 2: TRACE the data through ALL assignments and transformations — list each variable and function it flows through with line numbers.",
                "Step 3: At each step, is there any VALIDATION, SANITIZATION, or ENCODING applied? If so, is it sufficient for the specific vulnerability type?",
                "Step 4: What is the SINK — where does the data end up being used unsafely? What operation makes it dangerous?",
                "Step 5: Does the FRAMEWORK or LIBRARY provide automatic protections at this point (e.g., ORM parameterization, auto-escaping template engine, CSRF token)? If so, is it correctly configured and not bypassed?",
                "Step 6: What PRIVILEGE LEVEL or AUTHENTICATION STATE does an attacker need to trigger this code path — unauthenticated, authenticated user, or admin only?",
                "Step 7: What is the concrete SECURITY IMPACT if an attacker controls this data — RCE, data theft, privilege escalation, DoS?",
                "Step 8: Considering your answers above, identify the single WEAKEST LINK in the defense chain. If no weak link exists, explain what makes the defense complete.",
            ],
            context_hint="Must trace the complete data flow from source to sink. Include caller context.",
            additional_context=["caller", "struct", "global"],
        )

    def add_questions(self, questions: GuidedQuestions) -> None:
        """Add or update questions for a rule."""
        self.questions[questions.rule_id] = questions

    def has_questions(self, rule_id: str) -> bool:
        """Check if specific questions exist for a rule."""
        return rule_id in self.questions

    @property
    def rule_count(self) -> int:
        """Return number of rules with questions."""
        return len(self.questions)

    @property
    def rules(self) -> list[str]:
        """Return list of rule IDs with questions."""
        return list(self.questions.keys())
