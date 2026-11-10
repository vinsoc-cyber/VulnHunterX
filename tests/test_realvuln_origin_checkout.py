# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""RealVuln fp_origin classification and optional commit checkout."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from benchmarks.adapters.realvuln_adapter import RealVulnAdapter, _checkout_commit


def _write_manifest(root: Path, findings: list[dict], sha: str = "deadbeef") -> Path:
    d = root / "ground-truth" / "r"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "ground-truth.json"
    p.write_text(
        json.dumps(
            {
                "repo_id": "r",
                "repo_url": "https://example.com/r",
                "commit_sha": sha,
                "language": "python",
                "findings": findings,
            }
        )
    )
    return p


def _f(fid: str, vuln: bool, source: str, line: int = 1) -> dict:
    return {
        "id": fid,
        "is_vulnerable": vuln,
        "primary_cwe": "CWE-79",
        "file": "app.py",
        "location": {"start_line": line, "end_line": line, "function": "f"},
        "evidence": {"source": source},
    }


def test_fp_origin_classification(tmp_path):
    _write_manifest(
        tmp_path,
        [
            _f("t", False, "manual_review"),
            _f("n", False, "semgrep"),
            _f("u", False, "weird"),
            _f("v", True, "cve"),
        ],
    )
    by = {e.id.rsplit("-", 1)[-1]: e for e in RealVulnAdapter(tmp_path).load()}
    assert by["t"].metadata["fp_origin"] == "trap"
    assert by["n"].metadata["fp_origin"] == "natural"
    assert by["u"].metadata["fp_origin"] == "unknown"
    assert "fp_origin" not in by["v"].metadata
    assert "checkout" not in by["v"].metadata  # default behaviour unchanged


def test_checkout_skips_without_clone(tmp_path):
    _write_manifest(tmp_path, [_f("f", True, "cve")])
    e = RealVulnAdapter(tmp_path).load(checkout=True)[0]
    assert e.metadata["checkout"] == "skipped:not_a_clone"


def test_checkout_validation(tmp_path):
    d = tmp_path / "c"
    assert _checkout_commit(d, "r", "", "--upload-pack=x", False) == "skipped:invalid_sha"
    assert _checkout_commit(d, "r", "", "deadbeef", True) == "skipped:non_https_url"
    assert _checkout_commit(d, "r", "file:///etc", "deadbeef", True) == "skipped:non_https_url"
    assert _checkout_commit(d, "../x", "", "deadbeef", False) == "skipped:unsafe_repo_id"


def test_checkout_existing_clone(tmp_path):
    exe = shutil.which("git")
    if not exe:
        pytest.skip("no git binary")
    repo = tmp_path / "_repos" / "r"
    repo.mkdir(parents=True)

    def run(*a: str) -> str:
        return subprocess.run(
            [exe, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@e.x", *a],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    run("init", "-q")
    (repo / "app.py").write_text("v1\n")
    run("add", ".")
    run("commit", "-qm", "1")
    sha = run("rev-parse", "HEAD")
    (repo / "app.py").write_text("v2\n")
    run("commit", "-aqm", "2")
    _write_manifest(tmp_path, [_f("f", True, "cve")], sha=sha)
    e = RealVulnAdapter(tmp_path).load(checkout=True)[0]
    assert e.metadata["checkout"] == "ok"
    assert (repo / "app.py").read_text() == "v1\n"
