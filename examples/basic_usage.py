#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""
Basic example of using the CodeQL + LLM verification framework.

This script demonstrates how to use the Python API to verify CodeQL findings.
"""

from pathlib import Path
import sys

# Add src to path for development usage
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vuln_hunter_x import VerificationEngine, __version__
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.core.types import Finding, Verdict


def example_1_basic_verification():
    """Basic verification using config file."""
    print("=" * 60)
    print("Example 1: Basic verification with config file")
    print("=" * 60)
    
    # Create engine from config
    engine = VerificationEngine.from_config(
        Path("config/confirm_findings.yaml")
    )
    
    print(f"Loaded {engine.questions_loader.rule_count} question templates")
    print(f"Model: {engine.config.llm.model}")


def example_2_custom_config():
    """Verification with custom configuration."""
    print("=" * 60)
    print("Example 2: Custom configuration")
    print("=" * 60)
    
    # Create custom config (LLM mode: multi-turn with context expansion)
    config = Config.from_dict({
        "provider": "openai",
        "model": "gpt-4o-mini",  # Use cheaper model
        "max_iterations": 5,
        "temperature": 0.1,  # More deterministic
    })
    
    engine = VerificationEngine(config)
    
    print(f"Model: {config.llm.model}")
    print(f"Temperature: {config.llm.temperature}")


def example_3_progress_callbacks():
    """Using progress callbacks for real-time updates."""
    print("=" * 60)
    print("Example 3: Progress callbacks")
    print("=" * 60)
    
    engine = VerificationEngine.from_config(
        Path("config/confirm_findings.yaml")
    )
    
    def on_start(i: int, total: int, finding: Finding):
        print(f"[{i}/{total}] Starting: {finding.rule_id}")
        print(f"         File: {finding.location}")
    
    def on_complete(i: int, total: int, verdict: Verdict):
        print(f"         Verdict: {verdict.verdict} ({verdict.confidence})")
        print(f"         Time: {verdict.elapsed_seconds:.2f}s")
    
    # Set callbacks
    engine.on_finding_start(on_start)
    engine.on_finding_complete(on_complete)
    
    print("Callbacks configured - ready for verification")


def example_4_manual_components():
    """Using individual components manually."""
    print("=" * 60)
    print("Example 4: Manual component usage")
    print("=" * 60)
    
    from vuln_hunter_x.sarif.parser import parse_sarif_file, discover_sarif_files
    from vuln_hunter_x.questions.loader import QuestionsLoader
    from vuln_hunter_x.context.extractor import ContextExtractor
    
    # Discover SARIF files
    sarif_files = discover_sarif_files(Path("output"))
    print(f"Found {len(sarif_files)} SARIF files")
    
    # Load questions
    loader = QuestionsLoader(Path("config/prompts"))
    print(f"Loaded {loader.rule_count} question templates")
    
    # Get questions for a specific rule
    questions = loader.get_questions("cpp/use-after-free")
    print(f"Rule: {questions.rule_id}")
    print(f"Description: {questions.short_description}")
    print(f"Questions: {len(questions.questions)}")
    
    # Create context extractor
    extractor = ContextExtractor(Path("repos"))
    print("Context extractor ready")


def example_5_result_handling():
    """Working with verification results."""
    print("=" * 60)
    print("Example 5: Result handling")
    print("=" * 60)
    
    from vuln_hunter_x.core.types import VerificationResult
    
    # Create mock results
    finding = Finding(
        rule_id="cpp/buffer-overflow",
        message="Potential buffer overflow",
        file="src/buffer.c",
        start_line=42,
        end_line=42,
        repo_name="test-repo",
        lang="c",
    )
    
    verdict = Verdict(
        finding=finding,
        verdict="True Positive",
        confidence="High",
        reasoning="Buffer size is fixed but input is unbounded",
        answers=["The buffer is 256 bytes", "Input comes from user"],
        raw_response="...",
        model="gpt-4o",
    )
    
    result = VerificationResult(
        verdicts=[verdict],
        stats={"True Positive": 1},
        model="gpt-4o",
        provider="openai",
    )
    
    print(f"Total findings: {result.total_findings}")
    print(f"True positives: {result.true_positive_count}")
    print(f"False positive rate: {result.false_positive_rate:.1f}%")
    
    # Convert to dict for JSON serialization
    result_dict = result.to_dict()
    print(f"Result keys: {list(result_dict.keys())}")


def main():
    """Run all examples."""
    print(f"\nCodeQL + LLM Framework v{__version__} - Examples\n")
    
    example_1_basic_verification()
    print()
    
    example_2_custom_config()
    print()
    
    example_3_progress_callbacks()
    print()
    
    example_4_manual_components()
    print()
    
    example_5_result_handling()
    print()
    
    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
