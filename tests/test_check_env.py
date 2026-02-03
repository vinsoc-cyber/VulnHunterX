"""Phase 1: Test that check_env.py runs and reports CodeQL/OpenAI/Ollama status."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_ENV = REPO_ROOT / "scripts" / "check_env.py"


def test_check_env_runs_and_reports() -> None:
    """check_env.py runs and prints Phase 1 header and at least CodeQL line."""
    result = subprocess.run(
        [sys.executable, str(CHECK_ENV)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    out = result.stdout + result.stderr
    assert "Phase 1" in out, f"Expected 'Phase 1' in output: {out[:500]}"
    assert "CodeQL" in out, f"Expected 'CodeQL' in output: {out[:500]}"
    # Exit 0 (all ok) or 1 (some optional checks failed) are both valid
    assert result.returncode in (0, 1), f"Unexpected exit code {result.returncode}"
