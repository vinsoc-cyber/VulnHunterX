# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Interactive wizard for vuln-hunter-x.

Prompts the user for the inputs a full scan needs (source, language, rule
profile, LLM provider/model, finding limit) and then dispatches into
``cmd_scan``. Uses only the standard library ``input()`` so it adds no
dependency. Designed to be the friendliest entry point for new users.

Before prompting it runs an environment check and exits if no SAST analyzer is
available. As each answer is entered it is validated against the environment
(does the analyzer exist? does the path exist? does the LLM key work?) so
problems surface immediately instead of deep inside the pipeline.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from vuln_hunter_x.cli import env as envmod
from vuln_hunter_x.cli.commands import _SUPPORTED_LANGS, cmd_scan
from vuln_hunter_x.context.treesitter_extractor import LANG_EXTENSIONS

# Ordered for display; mirrors the CLI --lang choices.
_LANG_ORDER = ["c", "cpp", "python", "javascript", "php", "java", "go", "csharp"]
_PROFILES = ["standard", "extended", "maximum", "extended-registry", "full"]
_PROVIDERS = ["(use config/.env default)", "openai", "anthropic", "ollama", "deepseek"]

# Analyzer options: (token, label, predicate over the availability dict).
_TOOL_DEFS = [
    ("both", "both (codeql + semgrep)", lambda a: a["codeql"] or a["semgrep"]),
    ("codeql", "codeql", lambda a: a["codeql"]),
    ("semgrep", "semgrep", lambda a: a["semgrep"]),
    ("opengrep", "opengrep", lambda a: a["opengrep"]),
    ("all", "all (codeql + semgrep + opengrep)", lambda a: a["codeql"] or a["semgrep"] or a["opengrep"]),
]


def _prompt(text: str, default: str = "") -> str:
    """Prompt for free-text input, returning *default* on empty entry."""
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"{text}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130) from None
    return ans or default


def _prompt_choice(text: str, options: list[str], default_index: int = 0) -> str:
    """Prompt the user to pick one of *options* by number."""
    print(f"\n{text}")
    for i, opt in enumerate(options, 1):
        marker = " (default)" if i - 1 == default_index else ""
        print(f"  {i}. {opt}{marker}")
    while True:
        raw = _prompt("Choice", str(default_index + 1))
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        print(f"  Please enter a number between 1 and {len(options)}.")


def _check_prerequisites() -> dict[str, bool] | None:
    """Run the fast (no-network) environment checks before prompting.

    Returns an availability dict, or ``None`` when a hard prerequisite is
    missing (no SAST analyzer at all) and the caller should exit. The live LLM
    connectivity check is deferred to the provider prompt.
    """
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    semgrep_path = os.environ.get("SEMGREP_PATH", "semgrep")
    opengrep_path = os.environ.get("OPENGREP_PATH", "opengrep")

    checks = {
        "CodeQL": envmod.check_codeql(codeql_path),
        "Semgrep": envmod.check_semgrep(semgrep_path),
        "OpenGrep": envmod.check_opengrep(opengrep_path),
        "tree-sitter": envmod.check_treesitter(),
    }
    git_ok = shutil.which("git") is not None

    print("Checking prerequisites...")
    for name, (ok, msg) in checks.items():
        print(f"  [{'OK' if ok else '--'}] {name}: {msg}")
    print(
        f"  [{'OK' if git_ok else '--'}] git: "
        + ("found" if git_ok else "not on PATH (URL cloning unavailable)")
    )

    avail = {
        "codeql": checks["CodeQL"][0],
        "semgrep": checks["Semgrep"][0],
        "opengrep": checks["OpenGrep"][0],
        "treesitter": checks["tree-sitter"][0],
        "git": git_ok,
    }

    if not (avail["codeql"] or avail["semgrep"] or avail["opengrep"]):
        print(
            "\nNo SAST analyzer is available — CodeQL, Semgrep, and OpenGrep are all missing.\n"
            "Install at least one (e.g. `pip install semgrep`, or the CodeQL CLI) and retry.",
            file=sys.stderr,
        )
        return None
    if not avail["treesitter"]:
        print("  Note: tree-sitter missing — context extraction for verification will be degraded.")
    print()
    return avail


def _provider_live_check(provider: str, model: str | None) -> tuple[bool, str]:
    """Live-test connectivity for *provider* using the env.py checkers."""
    if provider == "openai":
        return envmod.check_openai(model=model or None)
    if provider == "anthropic":
        return envmod.check_anthropic(model=model or None)
    if provider == "ollama":
        eff_model = (
            model
            or os.environ.get("LLM_MODEL")
            or envmod.load_config_for_check().get("model")
        )
        return envmod.check_ollama(model=eff_model)
    if provider == "deepseek":
        # No dedicated checker — DeepSeek is OpenAI-compatible and LiteLLM reads
        # DEEPSEEK_API_KEY (falling back to OPENAI_API_KEY). Presence-check only.
        if os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY"):
            return True, "DeepSeek key present (connectivity not live-tested)"
        return False, "DEEPSEEK_API_KEY (or OPENAI_API_KEY) not set"
    return False, f"Unknown provider: {provider}"


def _select_source(scan: argparse.Namespace, avail: dict[str, bool]) -> None:
    """Prompt for and validate the scan source (URL or local directory)."""
    source_opts = ["A git repository URL (clone it)", "A local directory on this machine"]
    if not avail["git"]:
        print("\nNote: git is not available — URL cloning is disabled; use a local directory.")
    while True:
        source = _prompt_choice("What do you want to scan?", source_opts)
        if source.startswith("A git") and not avail["git"]:
            print("  git is required to clone a URL. Choose a local directory instead.")
            continue
        break

    if source.startswith("A git"):
        while True:
            url = _prompt("Git repository URL")
            if url and ("://" in url or url.startswith("git@") or url.endswith(".git")):
                scan.url = url
                return
            print("  Enter a valid git URL (https://… , git@… , or …​.git).")
    else:
        while True:
            path = _prompt("Local path")
            if not path:
                print("  A path is required.")
                continue
            resolved = Path(path).expanduser()
            if resolved.is_dir():
                scan.local_path = resolved
                return
            print(f"  Not a directory: {resolved}")


def _select_language(scan: argparse.Namespace) -> None:
    """Prompt for the language; in local-path mode warn if no matching files exist."""
    langs = [lang for lang in _LANG_ORDER if lang in _SUPPORTED_LANGS]
    langs += sorted(_SUPPORTED_LANGS - set(langs))
    default_index = langs.index("python") if "python" in langs else 0

    while True:
        scan.lang = _prompt_choice("Which language?", langs, default_index=default_index)
        if scan.local_path is None:
            return
        exts = LANG_EXTENSIONS.get(scan.lang, ())
        if not exts:
            return
        has_files = any(next(scan.local_path.rglob(f"*{e}"), None) is not None for e in exts)
        if has_files:
            return
        print(
            f"  Warning: no {scan.lang} files ({', '.join(exts)}) found under {scan.local_path}."
        )
        if _prompt("  Choose a different language? (y/n)", "n").lower() not in ("y", "yes"):
            return


def _select_analyzer(scan: argparse.Namespace, avail: dict[str, bool]) -> None:
    """Prompt for the analyzer, gating on availability from the env check."""
    while True:
        options = [
            label + ("" if pred(avail) else "  (unavailable — not installed)")
            for _tok, label, pred in _TOOL_DEFS
        ]
        choice = _prompt_choice("Which analyzer(s)?", options)
        tok, _label, pred = _TOOL_DEFS[options.index(choice)]
        if not pred(avail):
            print(f"  '{tok}' needs a tool that isn't installed. Pick another.")
            continue
        scan.tool = tok
        if tok in ("both", "all"):
            needed = ("codeql", "semgrep") if tok == "both" else ("codeql", "semgrep", "opengrep")
            missing = [t for t in needed if not avail[t]]
            if missing:
                print(f"  Note: {', '.join(missing)} unavailable — running with the rest.")
        return


def _select_provider(scan: argparse.Namespace) -> bool:
    """Prompt for the LLM provider and live-test it.

    Returns False if the user aborts. Sets ``scan.skip_verify`` when the user
    chooses to continue without verification after a failed check.
    """
    while True:
        choice = _prompt_choice("LLM provider for verification?", _PROVIDERS)
        if choice.startswith("("):
            cfg = envmod.load_config_for_check()
            eff_provider = os.environ.get("LLM_PROVIDER") or cfg.get("provider", "openai")
            eff_model = os.environ.get("LLM_MODEL") or cfg.get("model")
            scan.provider = None  # let scan/config resolve it
            scan.model = None
            label = f"config default ({eff_provider})"
        else:
            eff_provider = choice
            entered = _prompt("Model name (optional)")
            scan.provider = choice
            scan.model = entered or None
            eff_model = entered or None
            label = choice

        print(f"  Checking {label} connectivity...")
        ok, msg = _provider_live_check(eff_provider, eff_model)
        print(f"  [{'OK' if ok else 'FAIL'}] {msg}")
        if ok:
            return True

        recovery = _prompt_choice(
            "LLM verification is unavailable. What now?",
            [
                "Re-enter provider / model",
                "Continue without verification (analyze + report only)",
                "Abort",
            ],
        )
        if recovery.startswith("Re-enter"):
            continue
        if recovery.startswith("Continue"):
            scan.skip_verify = True
            return True
        return False


def cmd_interactive(args: argparse.Namespace) -> int:
    """Run the guided wizard, then hand off to ``cmd_scan``."""
    print("VulnHunterX interactive scan")
    print("============================\n")

    avail = _check_prerequisites()
    if avail is None:
        return 1

    print("Answer the prompts below; press Enter to accept the default.")

    # Build a scan Namespace pre-populated with the scan parser's defaults so
    # every attribute cmd_scan reads is present. Lazy import avoids a circular
    # import (main imports this module).
    from vuln_hunter_x.cli.main import _add_scan_args

    sub = argparse.ArgumentParser(add_help=False)
    _add_scan_args(sub)
    scan = sub.parse_args([])

    _select_source(scan, avail)
    _select_language(scan)

    name = _prompt("Repository name (optional, auto-derived if blank)")
    scan.name = name or None

    scan.profile = _prompt_choice("Rule profile?", _PROFILES)
    _select_analyzer(scan, avail)

    if not _select_provider(scan):
        print("Aborted.", file=sys.stderr)
        return 0

    limit = _prompt("Max findings to verify (blank = no limit)")
    if limit.isdigit():
        scan.limit = int(limit)

    # Confirm
    print("\nAbout to run:")
    src_desc = scan.url or (str(scan.local_path) if scan.local_path else "(config)")
    print(f"  source   : {src_desc}")
    print(f"  language : {scan.lang}")
    print(f"  profile  : {scan.profile}")
    print(f"  analyzer : {scan.tool}")
    print(f"  provider : {scan.provider or '(default)'}")
    print(f"  verify   : {'skipped' if scan.skip_verify else 'on'}")
    print(f"  limit    : {scan.limit if scan.limit else '(none)'}")
    if _prompt("\nProceed? (y/n)", "y").lower() not in ("y", "yes"):
        print("Aborted.", file=sys.stderr)
        return 0

    return cmd_scan(scan)
