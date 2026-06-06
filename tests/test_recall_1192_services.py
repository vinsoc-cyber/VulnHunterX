# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Recall regression for the 1192-services Go repo.

A source review found high-impact bugs the SAST+LLM pipeline missed
(false negatives). The statically-detectable ones are now covered by custom
Semgrep rules in ``config/semgrep-custom/go.yaml``. This test pins that recall:
it scans the *real* source with those rules and asserts each
``detectability == "static"`` ground-truth finding is detected at its line.

Skipped automatically when opengrep/semgrep is missing or the source tree is
not present (it lives under a benchmark-results dir that may not be checked out).
See output/go/1192-services/verification_results/evaluation.md for context.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVICES = REPO_ROOT / "benchmarks" / "results" / "test_proj" / "1192" / "services"
GROUND_TRUTH = REPO_ROOT / "benchmarks" / "results" / "test_proj" / "1192" / "ground-truth.json"
GO_RULES = REPO_ROOT / "config" / "semgrep-custom" / "go.yaml"


def _binary() -> str | None:
    for b in ("opengrep", "semgrep"):
        if shutil.which(b):
            return b
    return None


pytestmark = pytest.mark.skipif(
    _binary() is None or not SERVICES.is_dir() or not GROUND_TRUTH.is_file(),
    reason="opengrep/semgrep or 1192-services source/ground-truth not available",
)


def _static_findings() -> list[dict]:
    data = json.loads(GROUND_TRUTH.read_text())
    return [f for f in data.get("findings", []) if f.get("detectability") == "static"]


def _scan(target: Path) -> list[dict]:
    binary = _binary()
    assert binary
    cmd = [binary]
    if binary == "opengrep":
        cmd += ["scan", "--x-ignore-semgrepignore-files"]
    cmd += ["--config", str(GO_RULES), "--json", "--no-git-ignore", "--quiet", str(target)]
    res = subprocess.run([c for c in cmd if c], capture_output=True, text=True, timeout=120)
    if res.returncode not in (0, 1):
        pytest.fail(f"scan failed rc={res.returncode}: {res.stderr[:300]}")
    return json.loads(res.stdout or "{}").get("results", [])


@pytest.mark.parametrize("finding", _static_findings(), ids=lambda f: f["id"])
def test_static_false_negative_now_detected(finding: dict) -> None:
    target = SERVICES / finding["file"]
    assert target.is_file(), f"source file missing: {target}"
    results = _scan(target)
    want_line = finding["location"]["start_line"]
    hits = [r for r in results if r.get("start", {}).get("line") == want_line]
    assert hits, (
        f"{finding['id']} ({finding['vulnerability_class']}) expected a finding at "
        f"{finding['file']}:{want_line}, got lines "
        f"{[r.get('start', {}).get('line') for r in results]}"
    )
