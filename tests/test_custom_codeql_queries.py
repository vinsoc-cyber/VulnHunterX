# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Stage-4 quality gate for custom CodeQL queries.

For every ``*.ql`` file under ``config/codeql-custom/<lang>/src/`` we:

1. Verify the file declares the expected metadata header (``@id``, ``@tags``
   with a CWE tag, ``@kind``, ``@security-severity``).
2. Compile it via ``codeql query compile``. A compilation error is a hard
   failure — broken queries silently produce zero SARIF findings, which
   makes the verification engine see nothing and the issue is invisible
   until someone reads the CodeQL log.

If the ``codeql`` binary is not installed, the compile tests are skipped —
metadata tests still run since they need no toolchain.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CODEQL_CUSTOM = REPO_ROOT / "config" / "codeql-custom"


def _all_ql_files() -> list[Path]:
    if not CODEQL_CUSTOM.is_dir():
        return []
    return sorted(CODEQL_CUSTOM.glob("*/src/*.ql"))


def _codeql_available() -> bool:
    return shutil.which("codeql") is not None


@pytest.mark.parametrize("ql_path", _all_ql_files(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_ql_metadata_complete(ql_path: Path) -> None:
    """Every custom .ql must declare @id (matching guided rule_id form),
    @kind, a CWE tag, and @security-severity."""
    body = ql_path.read_text()

    # @id <lang>/<name>
    m = re.search(r"@id\s+(\S+)", body)
    assert m, f"{ql_path}: missing @id"
    rule_id = m.group(1)
    parent_dir = ql_path.parent.parent.name  # config/codeql-custom/<lang>/src/*.ql
    # Directory names use the full language name; @id prefixes use the short
    # guided-question form (javascript -> js, python -> py, csharp -> cs).
    expected_prefix = {"javascript": "js", "python": "py", "csharp": "cs"}.get(
        parent_dir, parent_dir
    )
    assert rule_id.startswith(expected_prefix + "/"), (
        f"{ql_path}: @id {rule_id!r} must start with '{expected_prefix}/' to match the "
        f"guided-question rule_id convention"
    )

    # @kind problem | path-problem
    assert re.search(r"@kind\s+(problem|path-problem)", body), \
        f"{ql_path}: missing @kind problem|path-problem"

    # @tags external/cwe/cwe-N
    assert re.search(r"@tags[^@]*external/cwe/cwe-\d+", body, re.DOTALL), \
        f"{ql_path}: missing CWE tag (expected 'external/cwe/cwe-N' in @tags block)"

    # @security-severity <float>
    sev = re.search(r"@security-severity\s+([\d.]+)", body)
    assert sev, f"{ql_path}: missing @security-severity"
    severity = float(sev.group(1))
    assert 0 <= severity <= 10, f"{ql_path}: @security-severity {severity} out of [0,10]"


@pytest.mark.skipif(
    not _codeql_available(),
    reason="codeql binary not installed — skipping compile gate",
)
@pytest.mark.parametrize("ql_path", _all_ql_files(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_ql_compiles(ql_path: Path) -> None:
    """codeql query compile must succeed — a broken query silently produces
    zero findings, which is invisible until verification runs and gets nothing."""
    result = subprocess.run(
        ["codeql", "query", "compile", str(ql_path)],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=ql_path.parent.parent,  # the qlpack root
    )
    if result.returncode != 0:
        # Filter the noisy "Pack ... via --additional-packs" warnings before failing
        relevant = "\n".join(
            line for line in (result.stdout + "\n" + result.stderr).splitlines()
            if "additional-packs" not in line and "To avoid these" not in line
        )
        pytest.fail(f"compile failed for {ql_path}:\n{relevant}")


def test_every_ql_has_qlpack_alongside() -> None:
    """Each language directory with .ql files must also have qlpack.yml and suite.qls."""
    if not CODEQL_CUSTOM.is_dir():
        pytest.skip("no codeql-custom/ directory")
    for lang_dir in sorted(CODEQL_CUSTOM.iterdir()):
        if not lang_dir.is_dir():
            continue
        ql_files = list((lang_dir / "src").glob("*.ql")) if (lang_dir / "src").is_dir() else []
        if not ql_files:
            continue
        assert (lang_dir / "qlpack.yml").is_file(), \
            f"{lang_dir} has .ql files but no qlpack.yml"
        assert (lang_dir / "suite.qls").is_file(), \
            f"{lang_dir} has .ql files but no suite.qls"
