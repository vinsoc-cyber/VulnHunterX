"""Phase 2: Test clone_and_db.py (config load and dry-run)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLONE_AND_DB = REPO_ROOT / "scripts" / "clone_and_db.py"
CONFIG = REPO_ROOT / "config" / "repos.yaml"


def _load_clone_and_db_module():
    spec = importlib.util.spec_from_file_location("clone_and_db", CLONE_AND_DB)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_config_exists() -> None:
    """config/repos.yaml exists and has repos key."""
    assert CONFIG.is_file(), f"Config missing: {CONFIG}"
    import yaml
    data = yaml.safe_load(CONFIG.read_text())
    assert "repos" in data
    assert isinstance(data["repos"], list)
    assert len(data["repos"]) >= 1


def test_clone_and_db_dry_run() -> None:
    """clone_and_db.py --dry-run runs and prints Phase 2 and repo names."""
    result = subprocess.run(
        [sys.executable, str(CLONE_AND_DB), "--dry-run"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, f"Exit {result.returncode}: {out[:500]}"
    assert "Phase 2" in out, f"Expected 'Phase 2' in output: {out[:500]}"
    assert "minimist" in out or "repos" in out.lower(), f"Expected repo/config in output: {out[:500]}"


def test_write_build_script() -> None:
    """Build command is written to a script so CodeQL gets a single path."""
    import tempfile
    mod = _load_clone_and_db_module()
    with tempfile.TemporaryDirectory() as d:
        repo_root = Path(d)
        script_path = mod._write_build_script(repo_root, "cmake . && make")
        assert script_path == repo_root / ".codeql_build.sh"
        content = script_path.read_text()
        assert content.startswith("#!/bin/sh")
        assert "set -e" in content
        assert "cmake . && make" in content
        assert script_path.stat().st_mode & 0o111
