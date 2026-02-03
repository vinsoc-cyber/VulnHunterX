"""Tests for the CodeQL + LLM verification framework."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import framework modules
from codeql_llm.core.types import Finding, Verdict, GuidedQuestions, VerificationResult
from codeql_llm.core.config import Config, load_config
from codeql_llm.sarif.parser import SarifParser, parse_sarif_file
from codeql_llm.context.extractor import ContextExtractor
from codeql_llm.context.provider import ContextProvider
from codeql_llm.questions.loader import QuestionsLoader
from codeql_llm.llm.prompts import PromptBuilder
from codeql_llm.llm.client import LLMClient


class TestFinding:
    """Tests for Finding data class."""
    
    def test_finding_creation(self):
        finding = Finding(
            rule_id="cpp/use-after-free",
            message="Use of pointer after free",
            file="src/buffer.c",
            start_line=42,
            end_line=42,
            repo_name="test-repo",
            lang="c",
        )
        
        assert finding.rule_id == "cpp/use-after-free"
        assert finding.location == "src/buffer.c:42"
    
    def test_finding_to_dict(self):
        finding = Finding(
            rule_id="py/sql-injection",
            message="SQL injection",
            file="app.py",
            start_line=10,
            end_line=15,
            repo_name="test",
            lang="python",
        )
        
        d = finding.to_dict()
        assert d["rule_id"] == "py/sql-injection"
        assert d["file"] == "app.py"


class TestGuidedQuestions:
    """Tests for GuidedQuestions data class."""
    
    def test_questions_creation(self):
        questions = GuidedQuestions(
            rule_id="cpp/buffer-overflow",
            short_description="Buffer overflow",
            questions=["Q1", "Q2", "Q3"],
            context_hint="Check buffer sizes",
            additional_context=["caller"],
        )
        
        assert questions.rule_id == "cpp/buffer-overflow"
        assert len(questions.questions) == 3


class TestConfig:
    """Tests for Config class."""
    
    def test_default_config(self):
        config = Config()
        
        assert config.llm.provider == "openai"
        assert config.llm.model == "gpt-4o"
        assert config.verification.mode == "vulnhalla"
    
    def test_config_from_dict(self):
        data = {
            "provider": "ollama",
            "model": "ollama/llama3.2",
            "mode": "simple",
            "max_iterations": 5,
        }
        
        config = Config.from_dict(data)
        
        assert config.llm.provider == "ollama"
        assert config.llm.model == "ollama/llama3.2"
        assert config.verification.mode == "simple"
        assert config.verification.max_iterations == 5
    
    def test_config_merge(self):
        config = Config()
        merged = config.merge_with_args(provider="ollama", mode="simple")
        
        assert merged.llm.provider == "ollama"
        assert merged.verification.mode == "simple"
        # Original unchanged
        assert config.llm.provider == "openai"


class TestQuestionsLoader:
    """Tests for QuestionsLoader."""
    
    def test_generic_questions(self):
        loader = QuestionsLoader()
        
        questions = loader.get_questions("unknown/rule-type")
        
        assert questions.rule_id == "unknown/rule-type"
        assert len(questions.questions) > 0
    
    def test_load_from_dict(self):
        loader = QuestionsLoader()
        
        loader.add_questions(GuidedQuestions(
            rule_id="cpp/test-rule",
            short_description="Test rule",
            questions=["Q1", "Q2"],
            context_hint="Test hint",
        ))
        
        assert loader.has_questions("cpp/test-rule")
        q = loader.get_questions("cpp/test-rule")
        assert q.short_description == "Test rule"


class TestPromptBuilder:
    """Tests for PromptBuilder."""
    
    def test_simple_mode_prompt(self):
        builder = PromptBuilder(mode="simple")
        
        assert "single interface" not in builder.system_prompt.lower()
        assert "security static-analysis" in builder.system_prompt.lower()
    
    def test_vulnhalla_mode_prompt(self):
        builder = PromptBuilder(mode="vulnhalla")
        
        assert "CRITICAL INSTRUCTIONS" in builder.system_prompt
        assert "context_needed" in builder.system_prompt
    
    def test_build_user_prompt(self):
        builder = PromptBuilder(mode="simple")
        
        finding = Finding(
            rule_id="cpp/buffer-overflow",
            message="Buffer overflow",
            file="test.c",
            start_line=10,
            end_line=10,
            repo_name="test",
            lang="c",
        )
        
        questions = GuidedQuestions(
            rule_id="cpp/buffer-overflow",
            short_description="Buffer overflow",
            questions=["What is the buffer size?"],
            context_hint="",
        )
        
        prompt = builder.build_user_prompt(finding, "void test() {}", questions, "test")
        
        assert "cpp/buffer-overflow" in prompt
        assert "Buffer overflow" in prompt
        assert "What is the buffer size?" in prompt


class TestSarifParser:
    """Tests for SARIF parsing."""
    
    def test_parse_simple_sarif(self, tmp_path):
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "results": [{
                    "ruleId": "test/rule",
                    "message": {"text": "Test message"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test.c"},
                            "region": {"startLine": 10, "endLine": 10},
                        }
                    }]
                }]
            }]
        }
        
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(json.dumps(sarif_data))
        
        findings = parse_sarif_file(sarif_file, "c", "test-repo")
        
        assert len(findings) == 1
        assert findings[0].rule_id == "test/rule"
        assert findings[0].start_line == 10


class TestContextExtractor:
    """Tests for ContextExtractor."""
    
    def test_fallback_context(self, tmp_path):
        extractor = ContextExtractor(repos_base=tmp_path)
        
        context = extractor.get_context("nonexistent.c", 10, "c")
        
        assert "Could not read file" in context.code
        assert context.function_name == "<unknown>"


class TestVerificationResult:
    """Tests for VerificationResult."""
    
    def test_result_stats(self):
        finding = Finding(
            rule_id="test",
            message="test",
            file="test.c",
            start_line=1,
            end_line=1,
            repo_name="test",
            lang="c",
        )
        
        verdicts = [
            Verdict(finding=finding, verdict="True Positive", confidence="High",
                   reasoning="", answers=[], raw_response="", model="test"),
            Verdict(finding=finding, verdict="False Positive", confidence="Low",
                   reasoning="", answers=[], raw_response="", model="test"),
        ]
        
        result = VerificationResult(
            verdicts=verdicts,
            stats={"True Positive": 1, "False Positive": 1},
            mode="vulnhalla",
            model="gpt-4o",
            provider="openai",
        )
        
        assert result.total_findings == 2
        assert result.true_positive_count == 1
        assert result.false_positive_rate == 50.0
