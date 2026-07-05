#!/usr/bin/env python3
"""benchmark — pluggable VHX benchmark CLI. Usage: python benchmark.py <mode> [args]."""
from __future__ import annotations
import argparse
from pathlib import Path

from modes import version_ab

BENCH = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="benchmark")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="preview; no LLM spend")
    sub = ap.add_subparsers(dest="mode", required=True)
    version_ab.add_args(sub.add_parser("versionab", help="version A/B verifier benchmark"))
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "versionab":
        return version_ab.run(args, BENCH)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
