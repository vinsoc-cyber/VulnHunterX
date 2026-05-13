# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Command-line interface for CodeQL + LLM verification."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from vuln_hunter_x import __version__
from vuln_hunter_x.cli.commands import (
    cmd_analyze,
    cmd_build_sanitized,
    cmd_check_env,
    cmd_extract_fuzz_context,
    cmd_fuzz_run,
    cmd_generate_fuzz_drivers,
    cmd_info,
    cmd_prepare,
    cmd_report,
    cmd_verify,
)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="vuln-hunter-x",
        description="CodeQL + LLM Bug Verification Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check environment
  vuln-hunter-x check-env

  # Prepare repos and create databases
  vuln-hunter-x prepare --lang c
  vuln-hunter-x prepare --url https://github.com/org/repo.git --lang go

  # Run analysis (CodeQL, Semgrep, or both)
  vuln-hunter-x analyze --repo c-ares
  vuln-hunter-x analyze --tool semgrep --local-path /path/to/project --lang python

  # Verify findings with LLM
  vuln-hunter-x verify --repo c-ares --lang c --report

  # Generate report from existing results
  vuln-hunter-x report --repo c-ares --lang c
""",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Check-env command
    subparsers.add_parser(
        "check-env",
        help="Check tools (CodeQL, Semgrep, OpenGrep) and LLM providers (OpenAI, Anthropic, Ollama)",
    )

    # Prepare command (clone + create DB)
    prepare_parser = subparsers.add_parser(
        "prepare",
        aliases=["clone"],
        help="Clone repos / register local paths and create CodeQL databases",
    )
    _add_prepare_args(prepare_parser)

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run CodeQL analysis on databases",
    )
    _add_analyze_args(analyze_parser)

    # Build-sanitized command (Stage 5: fuzz)
    build_sanitized_parser = subparsers.add_parser(
        "build-sanitized",
        help="Build repo with sanitizers for fuzz harness linking (C/C++ only)",
    )
    _add_build_sanitized_args(build_sanitized_parser)

    # Extract-fuzz-context command (Stage 6: fuzz)
    extract_fuzz_parser = subparsers.add_parser(
        "extract-fuzz-context",
        help="Extract fuzz context CSVs (function_signatures, includes) from C/C++ databases",
    )
    _add_extract_fuzz_context_args(extract_fuzz_parser)

    # Generate-fuzz-drivers command (Stage 7.1–7.3: fuzz)
    gen_drivers_parser = subparsers.add_parser(
        "generate-fuzz-drivers",
        help="Generate libFuzzer harness .cc from verified findings (C/C++ only)",
    )
    _add_generate_fuzz_drivers_args(gen_drivers_parser)

    # Fuzz-run command (Stage 8: optional)
    fuzz_run_parser = subparsers.add_parser(
        "fuzz-run",
        help="Run libFuzzer for compiled harnesses, collect crashes (C/C++ only)",
    )
    _add_fuzz_run_args(fuzz_run_parser)

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
    info_parser.add_argument("--config", type=Path, help="Path to configuration file")

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate markdown report from verification results",
    )
    _add_report_args(report_parser)

    return parser


def _add_prepare_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for prepare (clone) command."""
    parser.add_argument("--config", type=Path, help="Path to repos.yaml")
    parser.add_argument(
        "--url", help="Git repository URL (direct clone without repos.yaml)"
    )
    parser.add_argument(
        "--local-path",
        type=Path,
        help="Path to existing local repository (skip clone, create DB only)",
    )
    parser.add_argument("--name", help="Repository name (auto-derived from URL/path if omitted)")
    parser.add_argument(
        "--build-command", help="Build command for compiled languages (C/C++/Go)"
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript", "php", "java", "go"],
        help="Only this language (required with --url or --local-path)",
    )
    parser.add_argument("--repo", help="Only this repository (config mode filter)")
    parser.add_argument("--skip-clone", action="store_true", help="Skip git clone")
    parser.add_argument("--skip-db", action="store_true", help="Skip database creation")
    parser.add_argument("--ask-llm", action="store_true", help="Ask LLM on build failure")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")

    # Context extraction options (runs automatically after DB creation)
    parser.add_argument(
        "--skip-context",
        action="store_true",
        help="Skip automatic context extraction after DB creation",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "codeql", "treesitter"],
        default="auto",
        help="Context extraction backend (default: auto-detect)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force re-extraction of context CSVs even if they exist",
    )


def _add_analyze_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for analyze command."""
    parser.add_argument(
        "--tool",
        choices=["codeql", "semgrep", "opengrep", "both", "all"],
        default="codeql",
        help="Analyzer(s) to run: codeql, semgrep, opengrep, both (codeql+semgrep), all (default: codeql)",
    )
    parser.add_argument(
        "--local-path",
        type=Path,
        help="Analyze a local directory directly (requires --lang; --name optional)",
    )
    parser.add_argument("--name", help="Repository name (auto-derived from path if omitted)")
    parser.add_argument(
        "--semgrep-config",
        action="append",
        dest="semgrep_configs",
        help="Semgrep config, repeatable (default: auto)",
    )
    parser.add_argument(
        "--opengrep-config",
        action="append",
        dest="opengrep_configs",
        help="OpenGrep config, repeatable (default: auto)",
    )
    parser.add_argument(
        "--codeql-suite",
        help="CodeQL query suite (built-in ref or path to .qls)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to repos.yaml (for Semgrep/OpenGrep repo list)",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript", "php", "java", "go"],
        help="Only this language (required with --local-path)",
    )
    parser.add_argument("--repo", help="Only this repository")
    parser.add_argument("--json", action="store_true", help="Also output findings JSON")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output with command details"
    )
    parser.add_argument(
        "-f", "--force", action="store_true", help="Force re-analysis even if SARIF already exists"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help="Number of parallel CodeQL analyses (default: 2)",
    )

    # Rule profile & category
    parser.add_argument(
        "--profile",
        choices=["standard", "extended", "maximum", "extended-registry", "full"],
        default=None,
        help=(
            "Rule profile controlling breadth of analysis. "
            "standard: security-extended + auto (default); "
            "extended: + p/security-audit + p/secrets; "
            "maximum: security-and-quality + p/owasp-top-ten; "
            "extended-registry: 8 universal + per-language packs (no custom rules); "
            "full: extended-registry + custom CodeQL & Semgrep rules"
        ),
    )
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        help=(
            "Security category filter (repeatable). "
            "Options: injection xss auth crypto secrets memory-safety "
            "data-exposure deserialization xxe ssrf file-security dos"
        ),
    )


def _add_build_sanitized_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for build-sanitized command."""
    parser.add_argument("--config", type=Path, help="Path to repos.yaml")
    parser.add_argument("--lang", choices=["c", "cpp"], help="Only this language")
    parser.add_argument("--repo", help="Only this repository")
    parser.add_argument(
        "-f", "--force", action="store_true", help="Force rebuild even if manifest exists"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")


def _add_extract_fuzz_context_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for extract-fuzz-context command."""
    parser.add_argument("--config", type=Path, help="Path to config YAML (for paths)")
    parser.add_argument("--lang", choices=["c", "cpp"], help="Only this language")
    parser.add_argument("--repo", help="Only this repository")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")


def _add_generate_fuzz_drivers_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for generate-fuzz-drivers command."""
    parser.add_argument("--config", type=Path, help="Path to config YAML (for paths)")
    parser.add_argument("--lang", choices=["c", "cpp"], help="Only this language")
    parser.add_argument("--repo", help="Only this repository")
    parser.add_argument(
        "--verdict",
        default="tp,nmd",
        help="Verdict filter: tp,nmd (default), tp, nmd, all (use SARIF only)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print actions only, do not write .cc"
    )
    parser.add_argument(
        "--build", action="store_true", help="Compile and link harnesses (Stage 7.4)"
    )
    parser.add_argument(
        "--llm-fix", action="store_true", help="Use LLM to fix compile/link errors (Stage 7.5)"
    )
    parser.add_argument(
        "--max-fix-iterations",
        type=int,
        default=None,
        help="Max LLM fix attempts (default: from config, fallback 5)",
    )
    parser.add_argument(
        "--extra-include-dir",
        action="append",
        dest="extra_include_dirs",
        default=None,
        help="Extra -I path for harness compilation (repeatable)",
    )
    parser.add_argument(
        "--extra-lib-dir",
        action="append",
        dest="extra_lib_dirs",
        default=None,
        help="Extra -L path for harness linking (repeatable)",
    )
    parser.add_argument(
        "--extra-link-lib",
        action="append",
        dest="extra_link_libs",
        default=None,
        help="Extra -l library for harness linking (repeatable)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed build errors, commands, and LLM fix iterations",
    )


def _add_fuzz_run_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for fuzz-run command."""
    parser.add_argument("--config", type=Path, help="Path to config YAML (for paths)")
    parser.add_argument("--repo", help="Only this repository")
    parser.add_argument(
        "--timeout", type=int, default=60, help="Timeout per harness in seconds (default 60)"
    )
    parser.add_argument(
        "--max-fuzz-time", type=int, default=30, help="libFuzzer -max_total_time (default 30)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print actions only, do not run fuzzers"
    )
    parser.add_argument(
        "--triage", action="store_true", help="Triage crashes: extract stack traces and deduplicate"
    )
    parser.add_argument(
        "--parallel", type=int, default=1, help="Run N harnesses in parallel (default 1)"
    )
    parser.add_argument("--corpus", action="store_true", help="Use persistent corpus directories")
    parser.add_argument(
        "--rss-limit", type=int, default=0, help="RSS memory limit per fuzzer in MB (0=unlimited)"
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the verify command."""
    # Config
    parser.add_argument("--config", type=Path, help="Path to configuration file")

    # Local path mode
    parser.add_argument(
        "--local-path",
        type=Path,
        help="Verify findings for a local directory (requires --lang; looks up SARIF in output)",
    )
    parser.add_argument("--name", help="Repository name (auto-derived from path if omitted)")

    # LLM settings
    llm_group = parser.add_argument_group("LLM Settings")
    llm_group.add_argument(
        "--provider", choices=["openai", "ollama", "anthropic"], help="LLM provider"
    )
    llm_group.add_argument("--model", help="LLM model name")
    llm_group.add_argument("--temperature", type=float, help="LLM temperature (0.0-1.0)")
    llm_group.add_argument("--max-tokens", type=int, help="Maximum tokens in response")

    # Verification settings
    verify_group = parser.add_argument_group("Verification Settings")
    verify_group.add_argument("--max-iterations", type=int, help="Max LLM rounds")

    # Filters
    filter_group = parser.add_argument_group("Filters")
    filter_group.add_argument("--sarif", type=Path, help="Specific SARIF file to process")
    filter_group.add_argument("--repo", help="Only process this repository")
    filter_group.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript", "php", "java", "go"],
        help="Only this language",
    )
    filter_group.add_argument("--limit", type=int, help="Maximum findings to process")
    filter_group.add_argument(
        "--include-tests",
        action="store_true",
        help="Include findings under test/ or tests/ (default: exclude)",
    )
    filter_group.add_argument(
        "--category",
        action="append",
        dest="categories",
        help=(
            "Only verify findings in these security categories (repeatable). "
            "Options: injection xss auth crypto secrets memory-safety "
            "data-exposure deserialization xxe ssrf file-security dos"
        ),
    )

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    output_group.add_argument("--log-file", type=Path, help="Save LLM conversations to file")
    output_group.add_argument("--dry-run", action="store_true", help="Show what would be processed")


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    """Add arguments for the report command."""
    parser.add_argument(
        "--results-dir",
        type=Path,
        help="Path to verification_results directory",
    )
    parser.add_argument(
        "--repo", help="Repository name (for auto-discovering results)"
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript", "php", "java", "go"],
        help="Language (for auto-discovering results)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output path for the report (default: report.md in results dir)",
    )
    parser.add_argument(
        "--lang-report",
        choices=["en", "vi", "all"],
        default="all",
        help="Report language: en (English), vi (Vietnamese), all (both) — default: all",
    )


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    # Load .env file for environment variables (CODEQL_PATH, API keys, etc.)
    load_dotenv()

    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command == "check-env":
        return cmd_check_env(args)
    elif args.command in ("prepare", "clone"):
        return cmd_prepare(args)
    elif args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "build-sanitized":
        return cmd_build_sanitized(args)
    elif args.command == "extract-fuzz-context":
        return cmd_extract_fuzz_context(args)
    elif args.command == "generate-fuzz-drivers":
        return cmd_generate_fuzz_drivers(args)
    elif args.command == "fuzz-run":
        return cmd_fuzz_run(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "info":
        return cmd_info(args)
    elif args.command == "report":
        return cmd_report(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
