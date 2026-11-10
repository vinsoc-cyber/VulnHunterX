#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Build a silver-labelled revision-pair manifest from CVE fix commits.

For each fix spec the vulnerable (parent) and patched (fix) commits are checked
out, scanned with identical rules, and every vulnerable-side alert is labelled
automatically from the diff (tiers: silver-tp, silver-tp-weak, persistent,
ambiguous — see ``benchmarks/builders/revpair/label.py``). All labels are
``label_source="auto-diff"`` / ``adjudication="pending"``.

Input: JSONL, one fix spec per line (the format emitted by the CVEfixes
selector)::

    {
      "cve_id":        "CVE-2021-12345",            # required
      "cve_published": "2021-06-01",                # optional, copied to metadata
      "repo_url":      "https://github.com/o/p",    # required, https:// or git://
      "lang":          "c",                         # required: c cpp python javascript
                                                    #   php java go csharp
      "cwe":           "CWE-787",                   # required ("787" also accepted)
      "fix_sha":       "0123abcd...",               # required, 7-40 hex
      "parent_sha":    "89efcdab...",               # optional; default fix^ (merge
                                                    #   commits rejected unless given)
      "build_command": "make -j4",                  # optional; compiled langs only,
                                                    #   honoured only with --allow-build
      "repo":          "o_p"                        # optional workspace name override
    }

Outputs (under ``--output-dir``): ``cvefixes-<YYYYMMDD>.jsonl`` (+ ``.sha256``)
and ``revpair_attrition.json``. Scanner outputs go to ``<scan-output>/<lang>/
<repo>__<sha8>/`` with a ``REVISION`` marker; revisions are symlinked into
``<repos-dir>/<lang>/<repo>__<sha8>`` for later full-repo verification.

Network is used only to clone/fetch the user-supplied upstream URLs (and by
the scanners themselves if the selected profile uses registry rule packs,
e.g. Semgrep ``auto``). Compiled-language CodeQL builds execute target code
and are refused unless ``--allow-build`` is passed; prefer
``--build-container IMAGE`` (``docker run --network none``).

Examples::

    # Checkout + diff only (no scanners):
    python benchmarks/scripts/build_revpair_manifest.py --input fixes.jsonl --dry-run

    # OpenGrep (offline vendored rules) on interpreted-language fixes:
    python benchmarks/scripts/build_revpair_manifest.py --input fixes.jsonl \\
        --tools opengrep --profile standard --limit 20
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.builders.revpair.checkout import RevisionCheckout  # noqa: E402
from benchmarks.builders.revpair.manifest import write_attrition, write_manifest  # noqa: E402
from benchmarks.builders.revpair.runner import (  # noqa: E402
    SUPPORTED_TOOLS,
    AttritionLog,
    FixSpec,
    ScannerBackend,
    StaleRevisionError,
    process_fix,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build a revision-pair (parent vs fix) auto-labelled manifest.",
    )
    p.add_argument("--input", required=True, type=Path, help="JSONL of fix specs")
    p.add_argument(
        "--tools",
        default="opengrep",
        help=f"Comma-separated scanners from {','.join(SUPPORTED_TOOLS)} (default: opengrep)",
    )
    p.add_argument(
        "--profile", default="standard", help="Rule profile (config/rule_categories.yaml)"
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("output/revpair/cache"),
        help="Mirror + worktree cache",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output/revpair"),
        help="Where the manifest, its .sha256 and the attrition JSON are written",
    )
    p.add_argument("--scan-output", type=Path, default=Path("output"), help="Scanner output root")
    p.add_argument("--repos-dir", type=Path, default=Path("repos"), help="Workspace repos root")
    p.add_argument(
        "--manifest-name",
        default=f"cvefixes-{datetime.now(UTC):%Y%m%d}.jsonl",
        help="Manifest file name; the cvefixes-diff adapter finds cvefixes-*.jsonl by default",
    )
    p.add_argument(
        "--allow-build",
        action="store_true",
        help="Permit compiled-language CodeQL builds (executes target build code)",
    )
    p.add_argument(
        "--build-container",
        metavar="IMAGE",
        help="Run compiled-language CodeQL DB creation in 'docker run --network none IMAGE'",
    )
    p.add_argument("--limit", type=int, default=0, help="Process at most N specs (0 = all)")
    p.add_argument("--dry-run", action="store_true", help="Checkout + diff only, no scanners")
    p.add_argument("--force", action="store_true", help="Re-run scanners even if SARIF exists")
    p.add_argument(
        "--allow-local-repos",
        action="store_true",
        help="Accept absolute local repository paths as repo_url (testing only)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    bad = [t for t in tools if t not in SUPPORTED_TOOLS]
    if bad or not tools:
        p.error(f"--tools must be a subset of {SUPPORTED_TOOLS}, got {args.tools!r}")
    args.tool_list = tools
    if args.build_container and not args.allow_build:
        p.error("--build-container requires --allow-build")
    return args


def _read_specs(path: Path, allow_local: bool, attrition: AttritionLog) -> list[FixSpec]:
    specs: list[FixSpec] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                specs.append(FixSpec.from_dict(json.loads(line), allow_local=allow_local))
            except (ValueError, json.JSONDecodeError) as exc:
                attrition.record("spec", "invalid-spec", detail=f"line {lineno}: {exc}")
    return specs


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    attrition = AttritionLog()
    specs = _read_specs(args.input, args.allow_local_repos, attrition)
    if args.limit > 0:
        specs = specs[: args.limit]
    attrition.run_info = {
        "input": str(args.input),
        "tools": args.tool_list,
        "profile": args.profile,
        "dry_run": args.dry_run,
        "allow_build": args.allow_build,
        "build_container": args.build_container,
        "specs": len(specs),
    }
    checkout = RevisionCheckout(args.cache_dir, allow_local=args.allow_local_repos)
    backend = None
    if not args.dry_run:
        backend = ScannerBackend(
            repos_dir=args.repos_dir,
            allow_build=args.allow_build,
            build_container=args.build_container,
        )
    entries = []
    for i, spec in enumerate(specs, 1):
        print(f"[{i}/{len(specs)}] {spec.cve_id} {spec.repo_url} {spec.fix_sha[:12]}")
        try:
            got = process_fix(
                spec,
                checkout=checkout,
                backend=backend,
                tools=args.tool_list,
                profile=args.profile,
                output_dir=args.scan_output.resolve(),
                attrition=attrition,
                repos_dir=args.repos_dir.resolve(),
                dry_run=args.dry_run,
                force=args.force,
            )
        except StaleRevisionError as exc:
            attrition.record(
                "analyze",
                "stale-revision",
                cve_id=spec.cve_id,
                lang=spec.lang,
                cwe=spec.cwe,
                detail=str(exc),
            )
            print(f"  ERROR: {exc}", file=sys.stderr)
            continue
        print(f"  {len(got)} labelled entr{'y' if len(got) == 1 else 'ies'}")
        entries.extend(got)

    out_dir = args.output_dir
    attrition_path = out_dir / "revpair_attrition.json"
    write_attrition(attrition, attrition_path)
    print(f"Attrition: {attrition_path}")
    if args.dry_run:
        return 0
    manifest_path = out_dir / args.manifest_name
    digest = write_manifest(entries, manifest_path)
    print(f"Manifest: {manifest_path} ({len(entries)} entries, sha256 {digest[:16]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
