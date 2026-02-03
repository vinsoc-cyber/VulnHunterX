"""Phase 2: Test clone_and_db.py (config load and dry-run)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLONE_AND_DB = REPO_ROOT / "scripts" / "clone_and_db.py"
CONFIG = REPO_ROOT / "config" / "repos.yaml"


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
