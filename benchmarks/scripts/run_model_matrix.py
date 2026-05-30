#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Run the SAME benchmark across multiple models and collect the results.

The single-model runner (``run_benchmark.py``) evaluates one ``--model`` per
invocation. This orchestrator reads a model matrix from
``benchmarks/config/models.yaml`` (or ``--models id1,id2``) and launches one
``run_benchmark.py`` **subprocess per model** into its own results subdir, then
writes a ``matrix.json`` manifest. ``compare_models.py`` aggregates the members
into one side-by-side ``COMPARISON.md``.

Why subprocesses (not in-process): each provider needs an isolated credential
environment — DeepSeek sets ``OPENAI_BASE_URL`` + ``OPENAI_API_KEY``, plain
OpenAI must NOT have a base URL, Ollama uses ``OLLAMA_API_*``. These collide in
one process. A fresh subprocess with a per-model env gives clean isolation and
reuses 100% of run_benchmark's pricing/preflight/checkpoint/resume logic.

Examples:
    # Dry-run across the default matrix (no API cost)
    python benchmarks/scripts/run_model_matrix.py \
        --dataset secllmholmes --approach vulnhunterx --limit 10 --dry-run

    # Real run across two models on the security-rules dataset
    python benchmarks/scripts/run_model_matrix.py \
        --models gpt-4.1,deepseek-chat \
        --dataset security-rules --approach all

    # Forward dataset-specific flags after `--`
    python benchmarks/scripts/run_model_matrix.py --dataset juliet -- --juliet-per-cwe 20
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml
from dotenv import dotenv_values

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_BENCHMARK = _REPO_ROOT / "benchmarks" / "scripts" / "run_benchmark.py"
_MODELS_YAML = _REPO_ROOT / "benchmarks" / "config" / "models.yaml"
_RESULTS_DIR = _REPO_ROOT / "benchmarks" / "results"

# Credential / provider-selection keys that must be reset per model so a value
# from the parent shell or repo .env doesn't leak across providers (e.g. a
# DeepSeek OPENAI_BASE_URL bleeding into a plain-OpenAI run). Set to "" (not
# deleted) so run_benchmark's ``load_dotenv(override=False)`` treats them as
# present and does NOT re-inject them from the repo .env.
_ISOLATED_ENV_KEYS = (
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "ANTHROPIC_API_KEY",
    "OLLAMA_API_BASE",
    "OLLAMA_API_KEYS",
    "OLLAMA_API_KEY",
    "DEEPSEEK_API_KEY",
    "LLM_MODEL",
    "LLM_PROVIDER",
)


def _load_models(config_path: Path, selected: list[str] | None) -> list[dict]:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    models = raw.get("models", [])
    if not isinstance(models, list) or not models:
        raise ValueError(f"No 'models:' list found in {config_path}")
    by_id = {}
    for m in models:
        if "id" not in m or "model" not in m:
            raise ValueError(f"Model entry missing 'id'/'model': {m!r}")
        by_id[m["id"]] = m
    if selected:
        missing = [s for s in selected if s not in by_id]
        if missing:
            raise ValueError(
                f"unknown model id(s) {missing}; available: {sorted(by_id)}"
            )
        return [by_id[s] for s in selected]
    return list(models)


def _build_env(model: dict) -> dict[str, str]:
    """Per-model environment: parent env with provider keys reset, then the
    model's own .env file overlaid."""
    env = dict(os.environ)
    for k in _ISOLATED_ENV_KEYS:
        env[k] = ""  # block repo-.env re-injection (override=False)
    env_file = model.get("env")
    if env_file:
        path = (_REPO_ROOT / env_file).resolve()
        if not path.is_file():
            print(f"warning: env file not found for {model['id']}: {path}", file=sys.stderr)
        else:
            for key, val in dotenv_values(path).items():
                if val is not None:
                    env[key] = val
    return env


def _build_argv(model: dict, subdir: Path, common: list[str], extra: list[str]) -> list[str]:
    argv = [
        sys.executable,
        str(_RUN_BENCHMARK),
        "--model", str(model["model"]),
        "--provider", str(model.get("provider", "openai")),
        "--run-dir", str(subdir),
        *common,
        *extra,
    ]
    pricing = model.get("pricing")
    if pricing:
        argv += ["--pricing", str((_REPO_ROOT / pricing).resolve())]
    return argv


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a benchmark across a matrix of models.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--models-config", type=Path, default=_MODELS_YAML,
                        help=f"Path to models.yaml (default: {_MODELS_YAML}).")
    parser.add_argument("--models", default=None,
                        help="Comma-separated model ids to run (default: all in the config).")
    parser.add_argument("--dataset", default="secllmholmes",
                        help="Dataset to run (forwarded to run_benchmark). Use a "
                             "family tag ('owasp') or 'all' for multiple; "
                             "run the matrix again per dataset for an explicit set.")
    parser.add_argument("--approach", nargs="+", default=["vulnhunterx"],
                        help="Approach(es) to run (forwarded to run_benchmark).")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--jobs", "-j", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true",
                        help="Resume each member run from its checkpoint.")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--run-dir", type=Path, default=None,
                        help="Matrix parent dir (default: benchmarks/results/matrix_<timestamp>).")
    parser.add_argument("--continue-on-error", action="store_true",
                        help="Keep running remaining models if one fails (default: stop).")
    parser.add_argument("extra", nargs=argparse.REMAINDER,
                        help="Args after `--` are forwarded verbatim to each run_benchmark.")
    args = parser.parse_args()

    selected = [s.strip() for s in args.models.split(",")] if args.models else None
    try:
        models = _load_models(args.models_config, selected)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    matrix_dir = args.run_dir or (_RESULTS_DIR / f"matrix_{datetime.now():%Y%m%d_%H%M%S}")
    matrix_dir.mkdir(parents=True, exist_ok=True)

    # Flags shared by every member run.
    common: list[str] = ["--dataset", args.dataset, "--approach", *args.approach]
    if args.limit:
        common += ["--limit", str(args.limit)]
    if args.jobs is not None:
        common += ["--jobs", str(args.jobs)]
    if args.dry_run:
        common.append("--dry-run")
    if args.resume:
        common.append("--resume")
    if args.quiet:
        common.append("--quiet")

    # argparse.REMAINDER keeps a leading "--"; strip it.
    extra = list(args.extra)
    if extra and extra[0] == "--":
        extra = extra[1:]

    members: list[dict] = []
    print(f"▶  Model matrix: {len(models)} model(s) → {matrix_dir}", file=sys.stderr)
    for model in models:
        mid = model["id"]
        subdir = matrix_dir / mid
        subdir.mkdir(parents=True, exist_ok=True)
        env = _build_env(model)
        argv = _build_argv(model, subdir, common, extra)
        print(f"\n── {mid} ({model.get('provider', 'openai')}/{model['model']}) ──", file=sys.stderr)
        proc = subprocess.run(argv, env=env)  # noqa: S603 — argv is built from trusted config
        members.append({
            "model_id": mid,
            "provider": model.get("provider", "openai"),
            "model": model["model"],
            "tier": model.get("tier"),
            "subdir": mid,
            "pricing": model.get("pricing"),
            "returncode": proc.returncode,
        })
        if proc.returncode != 0 and not args.continue_on_error:
            print(f"error: model {mid} exited {proc.returncode}; stopping "
                  f"(use --continue-on-error to proceed)", file=sys.stderr)
            break

    manifest = {
        "matrix_dir": str(matrix_dir),
        "datasets": [args.dataset],
        "approaches": args.approach,
        "limit": args.limit,
        "dry_run": args.dry_run,
        "members": members,
    }
    (matrix_dir / "matrix.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n✓ matrix.json written: {matrix_dir / 'matrix.json'}", file=sys.stderr)
    print(f"  Next: python benchmarks/scripts/compare_models.py --run-dir {matrix_dir}",
          file=sys.stderr)

    failed = [m["model_id"] for m in members if m["returncode"] != 0]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
