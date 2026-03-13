"""Guided questions loading and management."""

from __future__ import annotations

from pathlib import Path

import yaml

from vuln_hunter_x.core.types import GuidedQuestions


class QuestionsLoader:
    """Loads and retrieves guided questions for CodeQL rules."""

    def __init__(self, prompts_dir: Path | None = None):
        self.questions: dict[str, GuidedQuestions] = {}
        self._default_questions: GuidedQuestions | None = None

        if prompts_dir:
            self.load_from_directory(prompts_dir)

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
            )

            if rule_id == "default":
                self._default_questions = questions
            else:
                self.questions[rule_id] = questions

            count += 1

        return count

    def get_questions(self, rule_id: str) -> GuidedQuestions:
        """
        Get guided questions for a rule, with fallback to default.

        Args:
            rule_id: The CodeQL rule ID (e.g., "cpp/use-after-free")

        Returns:
            GuidedQuestions for the rule
        """
        questions, _ = self.get_questions_with_match_info(rule_id)
        return questions

    def get_questions_with_match_info(self, rule_id: str) -> tuple[GuidedQuestions, str]:
        """
        Get guided questions for a rule and the match type used to find them.

        Match types (in order of preference):
          "exact"      — direct key lookup
          "normalized" — hyphens replaced with slashes
          "prefix"     — bidirectional prefix match
          "lang_prefix"— same language prefix, partial rule-name match
          "default"    — fell back to default_questions.yaml
          "generic"    — programmatically generated fallback

        Args:
            rule_id: The CodeQL rule ID (e.g., "cpp/use-after-free")

        Returns:
            (GuidedQuestions, match_type_str)
        """
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
            lang = parts[0]
            rule_name = "/".join(parts[1:])

            # Try to find similar rule in same language
            for key, q in self.questions.items():
                if key.startswith(f"{lang}/") and rule_name in key:
                    return q, "lang_prefix"

        # Return default or generate generic questions
        if self._default_questions:
            return GuidedQuestions(
                rule_id=rule_id,
                short_description=self._default_questions.short_description,
                questions=self._default_questions.questions,
                context_hint=self._default_questions.context_hint,
                additional_context=self._default_questions.additional_context,
            ), "default"

        return self._generate_generic_questions(rule_id), "generic"
    
    def _generate_generic_questions(self, rule_id: str) -> GuidedQuestions:
        """Generate generic questions for unknown rules."""
        return GuidedQuestions(
            rule_id=rule_id,
            short_description=f"CodeQL finding: {rule_id}",
            questions=[
                "What is the source of the potentially dangerous data?",
                "How does the data flow from source to the flagged sink?",
                "Are there any validation, sanitization, or encoding steps on the path?",
                "What is the security impact if this is exploited?",
                "Are there any mitigating factors in the broader context?",
            ],
            context_hint="Include the full function and trace the data flow",
            additional_context=["caller"],
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
