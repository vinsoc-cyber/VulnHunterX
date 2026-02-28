"""Tests for the CodeQL + LLM verification framework."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import framework modules
from vuln_hunter_x.core.types import Finding, Verdict, GuidedQuestions, VerificationResult
from vuln_hunter_x.core.config import Config, load_config
from vuln_hunter_x.sarif.parser import SarifParser, discover_sarif_files, parse_sarif_file
from vuln_hunter_x.context.extractor import ContextExtractor
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.llm.prompts import PromptBuilder
from vuln_hunter_x.llm.client import LLMClient


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
    
    def test_config_from_dict(self):
        data = {
            "provider": "ollama",
            "model": "ollama/llama3.2",
            "max_iterations": 5,
        }
        
        config = Config.from_dict(data)
        
        assert config.llm.provider == "ollama"
        assert config.llm.model == "ollama/llama3.2"
        assert config.verification.max_iterations == 5
    
    def test_config_merge(self):
        config = Config()
        merged = config.merge_with_args(provider="ollama", max_iterations=7)
        
        assert merged.llm.provider == "ollama"
        assert merged.verification.max_iterations == 7
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

    def test_load_from_directory_merges_multiple_files(self, tmp_path):
        """load_from_directory() should glob and merge all *_questions.yaml files."""
        (tmp_path / "cpp_questions.yaml").write_text(
            "cpp/test-rule:\n"
            "  short_description: 'cpp rule'\n"
            "  questions: ['Q1']\n"
            "  context_hint: 'hint'\n"
            "  additional_context: []\n",
            encoding="utf-8",
        )
        (tmp_path / "python_questions.yaml").write_text(
            "py/test-rule:\n"
            "  short_description: 'py rule'\n"
            "  questions: ['Q2']\n"
            "  context_hint: 'hint'\n"
            "  additional_context: []\n",
            encoding="utf-8",
        )
        loader = QuestionsLoader(tmp_path)
        assert loader.rule_count == 2
        assert loader.has_questions("cpp/test-rule")
        assert loader.has_questions("py/test-rule")
        assert loader.get_questions("cpp/test-rule").short_description == "cpp rule"
        assert loader.get_questions("py/test-rule").short_description == "py rule"

    def test_load_from_directory_ignores_non_yaml_files(self, tmp_path):
        """load_from_directory() must NOT load .txt or other non-yaml files."""
        (tmp_path / "notes.txt").write_text("ignore me")
        (tmp_path / "readme.md").write_text("# ignore me")
        loader = QuestionsLoader(tmp_path)
        assert loader.rule_count == 0  # no *_questions.yaml files found


class TestPromptBuilder:
    """Tests for PromptBuilder (LLM mode only)."""
    
    def test_system_prompt(self):
        builder = PromptBuilder()
        
        assert "CRITICAL INSTRUCTIONS" in builder.system_prompt
        assert "context_needed" in builder.system_prompt
        assert "security static-analysis" in builder.system_prompt.lower()
    
    def test_build_user_prompt(self):
        builder = PromptBuilder()
        
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

    def test_discover_sarif_files_codeql_and_semgrep(self, tmp_path):
        """Discover returns both CodeQL and Semgrep SARIF with correct repo_name."""
        output_dir = tmp_path / "output"
        lang_dir = output_dir / "c"
        repo_dir = lang_dir / "myrepo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "myrepo.sarif").write_text("{}")
        (repo_dir / "myrepo_semgrep.sarif").write_text("{}")
        results = discover_sarif_files(output_dir)
        assert len(results) == 2
        paths = {r[0].name for r in results}
        assert paths == {"myrepo.sarif", "myrepo_semgrep.sarif"}
        for _path, lang, repo_name in results:
            assert lang == "c"
            assert repo_name == "myrepo"


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
            model="gpt-4o",
            provider="openai",
        )
        
        assert result.total_findings == 2
        assert result.true_positive_count == 1
        assert result.false_positive_rate == 50.0
