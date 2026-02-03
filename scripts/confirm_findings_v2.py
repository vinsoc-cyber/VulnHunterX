#!/usr/bin/env python3
"""
Phase 4: Vulnhalla-Style Confirmation Flow - LLM-based Bug Verification.

This is the simplified version using the codeql_llm framework.

For each CodeQL finding in SARIF files, this script:
1. Extracts function context from the source code
2. Loads guided questions for the rule type
3. Sends context + questions to LLM (OpenAI or Ollama via LiteLLM)
4. Saves the verdict (True Positive / False Positive / Needs More Data)

Usage:
  python scripts/confirm_findings_v2.py [--provider openai|ollama] [--model MODEL]
                                        [--sarif PATH] [--repo NAME] [--limit N]
                                        [--dry-run] [--output-dir PATH]

Or use the CLI:
  codeql-llm verify [options]

Environment variables:
  OPENAI_API_KEY     - Required for OpenAI provider
  OLLAMA_API_BASE    - Optional, Ollama server URL (default: http://localhost:11434)
  LLM_PROVIDER       - Default provider: openai or ollama
  LLM_MODEL          - Default model (e.g., gpt-4o, ollama/llama3.2)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Load .env from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
if _REPO_ROOT.joinpath(".env").exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_REPO_ROOT / ".env")
    except ImportError:
        pass

# Add src to path for development
sys.path.insert(0, str(_REPO_ROOT / "src"))

from codeql_llm import __version__, VerificationEngine
from codeql_llm.core.config import load_config
from codeql_llm.core.types import Finding, Verdict
from codeql_llm.sarif.parser import discover_sarif_files, parse_sarif_file


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Phase 4: Confirm CodeQL findings with LLM (Vulnhalla-style)"
    )
    
    # Config
    parser.add_argument(
        "--config",
        type=Path,
        default=_REPO_ROOT / "config" / "confirm_findings.yaml",
        help="Path to configuration file",
    )
    
    # LLM settings
    parser.add_argument(
        "--provider",
        choices=["openai", "ollama"],
        help="LLM provider (default: from config or openai)",
    )
    parser.add_argument(
        "--model",
        help="LLM model name (default: from config or gpt-4o)",
    )
    parser.add_argument(
        "--mode",
        choices=["simple", "vulnhalla"],
        help="Verification mode (default: from config or vulnhalla)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        help="Max LLM rounds for vulnhalla mode (default: from config or 3)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        help="LLM temperature (default: from config or 0.2)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        help="Max tokens in response (default: from config or 1500)",
    )
    
    # Filters
    parser.add_argument(
        "--sarif",
        type=Path,
        help="Specific SARIF file to process",
    )
    parser.add_argument(
        "--repo",
        help="Only process findings from this repository",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript"],
        help="Only process findings from this language",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum findings to process (0 = all)",
    )
    
    # Output
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output with LLM prompts/responses",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Save full LLM conversations to markdown file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without calling LLM",
    )
    
    # Paths
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "output",
        help="Output directory for results",
    )
    
    args = parser.parse_args()
    
    # Load config
    config = load_config(args.config, _REPO_ROOT) if args.config.exists() else None
    
    # Build overrides
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
    if args.quiet:
        overrides["verbosity"] = "quiet"
    if args.verbose:
        overrides["verbosity"] = "verbose"
    if args.log_file:
        overrides["log_file"] = args.log_file
    
    if config and overrides:
        config = config.merge_with_args(**overrides)
    
    quiet = args.quiet
    
    # Print header
    if not quiet:
        print(f"CodeQL + LLM Bug Verification v{__version__}")
        if config:
            print(f"Mode: {config.verification.mode}")
            print(f"Provider: {config.llm.provider}, Model: {config.llm.model}")
        print()
    
    # Discover SARIF files
    output_dir = Path(args.output_dir)
    sarif_files = discover_sarif_files(output_dir)
    
    if args.sarif:
        # Single file mode
        if not args.sarif.is_file():
            print(f"Error: SARIF file not found: {args.sarif}", file=sys.stderr)
            return 1
        lang = args.lang or "c"
        sarif_files = [(args.sarif, lang, args.sarif.stem)]
    elif args.lang:
        sarif_files = [(p, l, n) for p, l, n in sarif_files if l == args.lang]
    if args.repo:
        sarif_files = [(p, l, n) for p, l, n in sarif_files if n.lower() == args.repo.lower()]
    
    if not sarif_files:
        print("No SARIF files found.")
        return 0
    
    # Collect findings
    all_findings: list[Finding] = []
    for sarif_path, lang, repo_name in sarif_files:
        findings = parse_sarif_file(sarif_path, lang, repo_name)
        all_findings.extend(findings)
        if not quiet:
            print(f"  [{lang}/{repo_name}] {len(findings)} findings")
    
    if not all_findings:
        print("No findings to verify.")
        return 0
    
    if args.limit > 0:
        all_findings = all_findings[:args.limit]
    
    if not quiet:
        print(f"\nTotal findings to process: {len(all_findings)}")
    
    # Dry-run mode
    if args.dry_run:
        print("\n[DRY RUN] Would process these findings:")
        for i, f in enumerate(all_findings[:10], 1):
            print(f"  {i}. {f.rule_id} @ {f.file}:{f.start_line}")
        if len(all_findings) > 10:
            print(f"  ... and {len(all_findings) - 10} more")
        return 0
    
    # Create engine
    engine = VerificationEngine.from_config(args.config, _REPO_ROOT, **overrides)
    
    if not quiet:
        print(f"\nLoaded {engine.questions_loader.rule_count} guided question templates")
    
    # Set up progress callbacks
    def on_start(i: int, total: int, finding: Finding) -> None:
        if quiet:
            print(f"[{i}/{total}] {finding.rule_id} @ {finding.file}:{finding.start_line}", end="", flush=True)
        else:
            print(f"\n[{i}/{total}] {finding.rule_id}")
            print(f"  File: {finding.file}:{finding.start_line}")
            print(f"  Message: {finding.message[:80]}...")
    
    def on_complete(i: int, total: int, verdict: Verdict) -> None:
        if quiet:
            print(f" -> {verdict.verdict} ({verdict.confidence})")
        else:
            print(f"  Verdict: {verdict.verdict} ({verdict.confidence})")
            if verdict.reasoning:
                print(f"  Reasoning: {verdict.reasoning[:100]}...")
            print(f"  Iterations: {verdict.iterations}, Time: {verdict.elapsed_seconds:.2f}s")
    
    engine.on_finding_start(on_start)
    engine.on_finding_complete(on_complete)
    
    # Open log file if specified
    log_file = None
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(args.log_file, 'w', encoding='utf-8')
        log_file.write(f"# LLM Verification Log\n\n")
        log_file.write(f"Generated: {__import__('datetime').datetime.now().isoformat()}\n")
        log_file.write(f"Mode: {config.verification.mode if config else 'default'}\n")
        log_file.write(f"Model: {config.llm.model if config else 'gpt-4o'}\n\n")
        log_file.write("---\n\n")
    
    try:
        # Run verification
        result = engine.verify_findings(all_findings, limit=args.limit)
        
        # Print summary
        print()
        print("=" * 60)
        print("Summary:")
        print(f"  Total: {result.total_findings}")
        for verdict_type, count in result.stats.items():
            if count > 0:
                pct = count / result.total_findings * 100 if result.total_findings else 0
                print(f"  {verdict_type}: {count} ({pct:.1f}%)")
        print(f"  Time: {result.total_time_seconds:.2f}s")
        
        # Save results
        summary_path, results_dir = engine.save_results(result, output_dir)
        print(f"\nResults saved to: {results_dir}")
        print(f"Summary: {summary_path}")
        
    finally:
        if log_file:
            log_file.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
