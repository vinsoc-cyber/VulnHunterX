#!/usr/bin/env python3
"""Tests for Phase 4: confirm_findings.py - Vulnhalla-Style Confirmation Flow."""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts to path for import
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from confirm_findings import (
    ContextExtractor,
    Finding,
    GuidedQuestions,
    LLMClient,
    QuestionsLoader,
    Verdict,
    parse_sarif,
)


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        f = Finding(
            rule_id="cpp/use-after-free",
            message="Pointer used after free",
            file="src/main.c",
            start_line=42,
            end_line=42,
            repo_name="test-repo",
            lang="c",
        )
        assert f.rule_id == "cpp/use-after-free"
        assert f.start_line == 42
        assert f.lang == "c"


class TestQuestionsLoader:
    """Test GuidedQuestionsLoader."""

    def test_load_questions(self, tmp_path):
        """Test loading guided questions from YAML."""
        yaml_content = """
cpp/use-after-free:
  short_description: "Use after free"
  questions:
    - "Where is the pointer freed?"
    - "Where is it used after?"
  context_hint: "Include full function"

default:
  short_description: "Generic finding"
  questions:
    - "What is the source?"
  context_hint: "Include context"
"""
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "guided_questions.yaml").write_text(yaml_content)

        loader = QuestionsLoader(prompts_dir)

        # Test exact match
        qs = loader.get_questions("cpp/use-after-free")
        assert qs.rule_id == "cpp/use-after-free"
        assert len(qs.questions) == 2
        assert "freed" in qs.questions[0]

        # Test fallback to default
        qs_default = loader.get_questions("unknown/rule")
        assert qs_default.rule_id == "default"

    def test_missing_file(self, tmp_path):
        """Test graceful handling of missing file."""
        loader = QuestionsLoader(tmp_path / "nonexistent")
        qs = loader.get_questions("any/rule")
        assert len(qs.questions) > 0  # Should have default questions


class TestContextExtractor:
    """Test ContextExtractor for function boundary detection."""

    def test_c_function_extraction(self, tmp_path):
        """Test extracting C function context."""
        c_code = """
#include <stdio.h>

void helper() {
    printf("helper\\n");
}

int main(int argc, char *argv[]) {
    char *ptr = malloc(100);
    free(ptr);
    printf("%s", ptr);  // Line 11 - use after free
    return 0;
}

void other() {
    // not relevant
}
"""
        # Setup repo structure
        repos_dir = tmp_path / "repos"
        c_repo = repos_dir / "c" / "test-repo"
        c_repo.mkdir(parents=True)
        (c_repo / "main.c").write_text(c_code)

        extractor = ContextExtractor(repos_dir)
        context, func_name, start, end = extractor.get_context(
            "main.c", 11, "c"
        )

        assert "malloc" in context
        assert "free" in context
        assert "printf" in context

    def test_python_function_extraction(self, tmp_path):
        """Test extracting Python function context."""
        py_code = """
import os

def helper():
    pass

def vulnerable_function(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"  # Line 8
    return query

def other():
    pass
"""
        repos_dir = tmp_path / "repos"
        py_repo = repos_dir / "python" / "test-repo"
        py_repo.mkdir(parents=True)
        (py_repo / "app.py").write_text(py_code)

        extractor = ContextExtractor(repos_dir)
        context, func_name, start, end = extractor.get_context(
            "app.py", 8, "python"
        )

        assert "vulnerable_function" in context or "user_input" in context
        assert "SELECT" in context

    def test_fallback_context(self, tmp_path):
        """Test fallback when file not found."""
        extractor = ContextExtractor(tmp_path / "repos")
        context, func_name, start, end = extractor.get_context(
            "nonexistent.c", 10, "c"
        )

        assert "Could not read" in context or func_name == "<unknown>"


class TestSarifParser:
    """Test SARIF parsing."""

    def test_parse_sarif(self, tmp_path):
        """Test parsing a SARIF file."""
        sarif_data = {
            "runs": [{
                "results": [
                    {
                        "ruleId": "cpp/use-after-free",
                        "message": {"text": "Pointer used after free"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.c"},
                                "region": {"startLine": 42, "endLine": 42}
                            }
                        }]
                    },
                    {
                        "ruleId": "cpp/buffer-overflow",
                        "message": {"text": "Buffer overflow"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/util.c"},
                                "region": {"startLine": 100}
                            }
                        }]
                    }
                ]
            }]
        }

        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(json.dumps(sarif_data))

        findings = parse_sarif(sarif_file, "c", "test-repo")

        assert len(findings) == 2
        assert findings[0].rule_id == "cpp/use-after-free"
        assert findings[0].file == "src/main.c"
        assert findings[0].start_line == 42
        assert findings[1].rule_id == "cpp/buffer-overflow"
        assert findings[1].start_line == 100

    def test_parse_empty_sarif(self, tmp_path):
        """Test parsing SARIF with no results."""
        sarif_data = {"runs": [{"results": []}]}
        sarif_file = tmp_path / "empty.sarif"
        sarif_file.write_text(json.dumps(sarif_data))

        findings = parse_sarif(sarif_file, "c", "test-repo")
        assert len(findings) == 0

    def test_parse_nonexistent_sarif(self, tmp_path):
        """Test parsing nonexistent file."""
        findings = parse_sarif(tmp_path / "nonexistent.sarif", "c", "test")
        assert len(findings) == 0


class TestLLMClient:
    """Test LLM client functionality."""

    def test_build_prompt(self):
        """Test prompt building."""
        client = LLMClient("openai", "gpt-4o")

        finding = Finding(
            rule_id="cpp/use-after-free",
            message="Pointer used after free",
            file="main.c",
            start_line=42,
            end_line=42,
        )

        questions = GuidedQuestions(
            rule_id="cpp/use-after-free",
            short_description="Use of freed pointer",
            questions=["Where is it freed?", "Where is it used?"],
            context_hint="Include full function",
        )

        prompt = client.build_prompt(
            finding,
            "void test() { free(ptr); use(ptr); }",
            questions,
            "test",
        )

        assert "cpp/use-after-free" in prompt
        assert "main.c" in prompt
        assert "42" in prompt
        assert "Where is it freed?" in prompt
        assert "free(ptr)" in prompt

    def test_parse_json_response(self):
        """Test parsing JSON from LLM response."""
        client = LLMClient("openai", "gpt-4o")

        # Direct JSON
        raw = '{"verdict": "True Positive", "confidence": "High", "reasoning": "Clear UAF", "answers": ["freed at line 5", "used at line 8"]}'
        parsed = client._parse_response(raw)
        assert parsed["verdict"] == "True Positive"
        assert parsed["confidence"] == "High"

        # JSON in markdown block
        raw_md = '''Here's my analysis:

```json
{"verdict": "False Positive", "confidence": "Medium", "reasoning": "Pointer is reassigned", "answers": ["Q1 answer"]}
```'''
        parsed_md = client._parse_response(raw_md)
        assert parsed_md["verdict"] == "False Positive"

    @patch("confirm_findings.litellm")
    def test_analyze_success(self, mock_litellm):
        """Test successful LLM analysis."""
        # Mock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "verdict": "True Positive",
            "confidence": "High",
            "reasoning": "Clear vulnerability",
            "answers": ["Answer 1", "Answer 2"],
        })
        mock_litellm.completion.return_value = mock_response

        client = LLMClient("openai", "gpt-4o")

        finding = Finding(
            rule_id="test/rule",
            message="Test message",
            file="test.c",
            start_line=1,
            end_line=1,
        )

        questions = GuidedQuestions(
            rule_id="test/rule",
            short_description="Test",
            questions=["Q1?"],
            context_hint="",
        )

        verdict = client.analyze(finding, "code", questions, "test_func")

        assert verdict.verdict == "True Positive"
        assert verdict.confidence == "High"
        assert len(verdict.answers) == 2


class TestVerdict:
    """Test Verdict dataclass."""

    def test_verdict_creation(self):
        finding = Finding(
            rule_id="test",
            message="msg",
            file="f.c",
            start_line=1,
            end_line=1,
        )

        verdict = Verdict(
            finding=finding,
            verdict="True Positive",
            confidence="High",
            reasoning="Clear bug",
            answers=["A1", "A2"],
            raw_response="...",
            model="gpt-4o",
            elapsed_seconds=1.5,
        )

        assert verdict.verdict == "True Positive"
        assert verdict.elapsed_seconds == 1.5
        assert len(verdict.timestamp) > 0  # Auto-generated


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
