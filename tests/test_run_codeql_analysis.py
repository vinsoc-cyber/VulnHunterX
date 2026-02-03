"""Phase 3: Test run_codeql_analysis.py (discovery and dry-run)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_ANALYSIS = REPO_ROOT / "scripts" / "run_codeql_analysis.py"
DATABASES_DIR = REPO_ROOT / "databases"
OUTPUT_DIR = REPO_ROOT / "output"


def test_run_codeql_analysis_dry_run_no_dbs() -> None:
    """With no DBs, script exits 1 and prints 'No CodeQL databases found'."""
    result = subprocess.run(
        [sys.executable, str(RUN_ANALYSIS), "--dry-run", "--databases-dir", str(REPO_ROOT / "nonexistent")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=15,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 1
    assert "No CodeQL databases found" in out or "discover" in out.lower() or "databases" in out


def test_run_codeql_analysis_dry_run_with_fake_db() -> None:
    """With a fake DB dir (codeql-database.yml), script discovers it and dry-runs analyze."""
    fake_db = DATABASES_DIR / "javascript" / "minimist"
    fake_db.mkdir(parents=True, exist_ok=True)
    (fake_db / "codeql-database.yml").write_text("# fake\n")
    try:
        result = subprocess.run(
            [sys.executable, str(RUN_ANALYSIS), "--dry-run", "--output-dir", str(OUTPUT_DIR)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=15,
        )
        out = result.stdout + result.stderr
        assert "Phase 3" in out, f"Expected 'Phase 3' in output: {out[:500]}"
        assert "minimist" in out, f"Expected 'minimist' in output: {out[:500]}"
        assert result.returncode == 0, f"Expected exit 0: {out}"
    finally:
        if (fake_db / "codeql-database.yml").exists():
            (fake_db / "codeql-database.yml").unlink()
        if fake_db.exists():
            try:
                fake_db.rmdir()
            except OSError:
                pass
        parent = fake_db.parent
        if parent.exists() and not any(parent.iterdir()):
            try:
                parent.rmdir()
            except OSError:
                pass
        if DATABASES_DIR.exists() and not any(DATABASES_DIR.iterdir()):
            try:
                DATABASES_DIR.rmdir()
            except OSError:
                pass


def test_sarif_to_findings() -> None:
    """sarif_to_findings parses minimal SARIF and returns findings list."""
    # Import from script (same repo)
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_codeql_analysis", RUN_ANALYSIS)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    findings = mod.sarif_to_findings(Path("/nonexistent"))
    assert findings == []
    # Minimal SARIF with one result
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        f.write('{"runs":[{"results":[{"ruleId":"x","message":{"text":"msg"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"f.c"},"region":{"startLine":1,"endLine":2}}}]}]}]}')
        path = Path(f.name)
    try:
        findings = mod.sarif_to_findings(path)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "x"
        assert findings[0]["message"] == "msg"
        assert findings[0]["file"] == "f.c"
        assert findings[0]["start_line"] == 1
        assert findings[0]["end_line"] == 2
    finally:
        path.unlink(missing_ok=True)
