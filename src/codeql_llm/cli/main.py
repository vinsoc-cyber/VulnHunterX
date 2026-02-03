"""Command-line interface for CodeQL + LLM verification."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from codeql_llm import __version__
from codeql_llm.core.config import Config, load_config
from codeql_llm.core.types import Finding, Verdict
from codeql_llm.verification.engine import VerificationEngine


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="codeql-llm",
        description="CodeQL + LLM Bug Verification Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify all findings with default settings
  codeql-llm verify

  # Verify specific repository
  codeql-llm verify --repo c-ares --lang c

  # Use Ollama instead of OpenAI
  codeql-llm verify --provider ollama --model ollama/llama3.2

  # Quick scan with simple mode
  codeql-llm verify --mode simple -q --limit 10
""",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify CodeQL findings using LLM",
    )
    _add_verify_args(verify_parser)
    
    # Info command
    info_parser = subparsers.add_parser(
        "info",
        help="Show configuration and environment info",
    )
    info_parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file",
    )
    
    return parser


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the verify command."""
    # Config
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file",
    )
    
    # LLM settings
    llm_group = parser.add_argument_group("LLM Settings")
    llm_group.add_argument(
        "--provider",
        choices=["openai", "ollama"],
        help="LLM provider",
    )
    llm_group.add_argument(
        "--model",
        help="LLM model name",
    )
    llm_group.add_argument(
        "--temperature",
        type=float,
        help="LLM temperature (0.0-1.0)",
    )
    llm_group.add_argument(
        "--max-tokens",
        type=int,
        help="Maximum tokens in response",
    )
    
    # Verification settings
    verify_group = parser.add_argument_group("Verification Settings")
    verify_group.add_argument(
        "--mode",
        choices=["simple", "vulnhalla"],
        help="Verification mode",
    )
    verify_group.add_argument(
        "--max-iterations",
        type=int,
        help="Maximum LLM conversation rounds (vulnhalla mode)",
    )
    
    # Filters
    filter_group = parser.add_argument_group("Filters")
    filter_group.add_argument(
        "--sarif",
        type=Path,
        help="Specific SARIF file to process",
    )
    filter_group.add_argument(
        "--repo",
        help="Only process this repository",
    )
    filter_group.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript"],
        help="Only process this language",
    )
    filter_group.add_argument(
        "--limit",
        type=int,
        help="Maximum findings to process",
    )
    
    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output with LLM prompts/responses",
    )
    output_group.add_argument(
        "--log-file",
        type=Path,
        help="Save full LLM conversations to file",
    )
    output_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without calling LLM",
    )
    
    # Paths
    paths_group = parser.add_argument_group("Paths")
    paths_group.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for results",
    )
    paths_group.add_argument(
        "--repos-dir",
        type=Path,
        help="Repositories directory",
    )


def cmd_verify(args: argparse.Namespace) -> int:
    """Execute the verify command."""
    # Load config
    base_path = Path.cwd()
    if args.config:
        config = load_config(args.config, base_path)
    else:
        default_config = base_path / "config" / "confirm_findings.yaml"
        config = load_config(default_config, base_path) if default_config.exists() else Config()
    
    # Build overrides from args
    overrides = {}
    if args.provider:
        overrides["provider"] = args.provider
    if args.model:
        overrides["model"] = args.model
    if args.mode:
        overrides["mode"] = args.mode
    if args.max_iterations:
        overrides["max_iterations"] = args.max_iterations
    if args.temperature:
        overrides["temperature"] = args.temperature
    if args.max_tokens:
        overrides["max_tokens"] = args.max_tokens
    if args.limit:
        overrides["limit"] = args.limit
    if args.quiet:
        overrides["verbosity"] = "quiet"
    if args.verbose:
        overrides["verbosity"] = "verbose"
    if args.log_file:
        overrides["log_file"] = args.log_file
    
    if overrides:
        config = config.merge_with_args(**overrides)
    
    quiet = config.output.is_quiet
    
    # Print header
    if not quiet:
        print(f"CodeQL + LLM Bug Verification v{__version__}")
        print(f"Mode: {config.verification.mode}")
        print(f"Provider: {config.llm.provider}, Model: {config.llm.model}")
        print()
    
    # Create engine
    engine = VerificationEngine(config)
    
    if not quiet:
        print(f"Loaded {engine.questions_loader.rule_count} guided question templates")
    
    # Set up progress callbacks
    def on_start(i: int, total: int, finding: Finding) -> None:
        if quiet:
            print(f"[{i}/{total}] {finding.rule_id} @ {finding.location}", end="", flush=True)
        else:
            print(f"\n[{i}/{total}] {finding.rule_id}")
            print(f"  File: {finding.location}")
    
    def on_complete(i: int, total: int, verdict: Verdict) -> None:
        if quiet:
            print(f" -> {verdict.verdict} ({verdict.confidence})")
        else:
            print(f"  Verdict: {verdict.verdict} ({verdict.confidence})")
            print(f"  Reasoning: {verdict.reasoning[:100]}...")
    
    engine.on_finding_start(on_start)
    engine.on_finding_complete(on_complete)
    
    # Determine what to verify
    if args.sarif:
        result = engine.verify_sarif(
            args.sarif,
            lang=args.lang or "c",
            repo_name=args.sarif.stem,
            limit=args.limit or 0,
        )
    else:
        result = engine.verify_all_sarif(
            lang_filter=args.lang,
            repo_filter=args.repo,
            limit=args.limit or 0,
        )
    
    # Print summary
    print()
    print("=" * 60)
    print("Summary:")
    print(f"  Total: {result.total_findings}")
    for verdict_type, count in result.stats.items():
        if count > 0:
            pct = count / result.total_findings * 100
            print(f"  {verdict_type}: {count} ({pct:.1f}%)")
    print(f"  Time: {result.total_time_seconds:.2f}s")
    
    # Save results
    summary_path, results_dir = engine.save_results(result)
    print(f"\nResults saved to: {results_dir}")
    print(f"Summary: {summary_path}")
    
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Execute the info command."""
    print(f"CodeQL + LLM Bug Verification v{__version__}")
    print()
    
    base_path = Path.cwd()
    if args.config:
        config = load_config(args.config, base_path)
        print(f"Config file: {args.config}")
    else:
        default_config = base_path / "config" / "confirm_findings.yaml"
        if default_config.exists():
            config = load_config(default_config, base_path)
            print(f"Config file: {default_config}")
        else:
            config = Config()
            print("Config file: (using defaults)")
    
    print()
    print("LLM Settings:")
    print(f"  Provider: {config.llm.provider}")
    print(f"  Model: {config.llm.model}")
    print(f"  Temperature: {config.llm.temperature}")
    print(f"  Max tokens: {config.llm.max_tokens}")
    
    print()
    print("Verification Settings:")
    print(f"  Mode: {config.verification.mode}")
    print(f"  Max iterations: {config.verification.max_iterations}")
    
    print()
    print("Paths:")
    print(f"  Repos: {config.paths.repos_dir}")
    print(f"  Databases: {config.paths.databases_dir}")
    print(f"  Output: {config.paths.output_dir}")
    print(f"  Context: {config.paths.context_dir}")
    
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    if args.command == "verify":
        return cmd_verify(args)
    elif args.command == "info":
        return cmd_info(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
