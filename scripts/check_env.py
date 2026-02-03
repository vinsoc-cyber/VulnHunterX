#!/usr/bin/env python3
"""
Phase 1 environment check: CodeQL CLI, OpenAI, and Ollama via LiteLLM.

Verifies:
- CodeQL CLI on PATH (or CODEQL_PATH)
- OpenAI API (if OPENAI_API_KEY set)
- Ollama LLM (local or remote via OLLAMA_API_BASE)

Usage:
  python scripts/check_env.py
  CODEQL_PATH=/path/to/codeql python scripts/check_env.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

# Load .env from repo root when run as script
_REPO_ROOT = Path(__file__).resolve().parent.parent
if _REPO_ROOT.joinpath(".env").exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_REPO_ROOT / ".env")
    except ImportError:
        pass

# Optional: litellm only when needed
try:
    import litellm
except ImportError:
    litellm = None


def check_codeql() -> tuple[bool, str]:
    """Verify CodeQL CLI is available and report version."""
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    if codeql_path != "codeql":
        if not os.path.isfile(codeql_path) and not shutil.which(codeql_path):
            return False, f"CODEQL_PATH set but not found: {codeql_path}"
    else:
        if not shutil.which("codeql"):
            return False, "CodeQL not on PATH; set CODEQL_PATH or install CodeQL CLI."
    try:
        out = subprocess.run(
            [codeql_path, "version", "--quiet"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=_REPO_ROOT,
        )
        if out.returncode != 0:
            return False, f"codeql version failed: {out.stderr or out.stdout}"
        version = (out.stdout or "").strip() or "unknown"
        return True, version
    except subprocess.TimeoutExpired:
        return False, "codeql version timed out"
    except FileNotFoundError:
        return False, f"CodeQL executable not found: {codeql_path}"
    except Exception as e:
        return False, str(e)


def check_openai() -> tuple[bool, str]:
    """Verify OpenAI API via LiteLLM (optional if no key)."""
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return False, "OPENAI_API_KEY not set (optional for Phase 1)"
    if litellm is None:
        return False, "litellm not installed; run: uv pip install litellm python-dotenv"
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    try:
        resp = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            api_key=api_key,
            max_tokens=10,
        )
        text = (resp.choices[0].message.content or "").strip()
        return True, f"OpenAI ({model}): {text[:50]}"
    except Exception as e:
        return False, f"OpenAI error: {e}"


def check_ollama() -> tuple[bool, str]:
    """Verify Ollama via LiteLLM (optional if not running). Supports remote server via OLLAMA_API_BASE."""
    if litellm is None:
        return False, "litellm not installed; run: uv pip install litellm python-dotenv"
    model = os.environ.get("OLLAMA_MODEL", "ollama/llama3.2")
    if not model.startswith("ollama/"):
        model = f"ollama/{model}"
    api_base = (os.environ.get("OLLAMA_API_BASE") or os.environ.get("OLLAMA_BASE_URL") or "").strip()
    api_base = api_base or None  # LiteLLM uses default http://localhost:11434 when None
    try:
        kwargs: dict = {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
            "max_tokens": 10,
        }
        if api_base:
            kwargs["api_base"] = api_base.rstrip("/")
        resp = litellm.completion(**kwargs)
        text = (resp.choices[0].message.content or "").strip()
        base_info = f" @ {api_base}" if api_base else ""
        return True, f"Ollama ({model}){base_info}: {text[:50]}"
    except Exception as e:
        return False, f"Ollama error: {e}"


def main() -> int:
    print("Phase 1: Environment check (CodeQL + LLM)\n")
    all_ok = True

    # CodeQL (required for later phases)
    ok, msg = check_codeql()
    status = "OK" if ok else "FAIL"
    print(f"  CodeQL: [{status}] {msg}")
    if not ok:
        all_ok = False

    # OpenAI (optional)
    ok, msg = check_openai()
    status = "OK" if ok else "SKIP/FAIL"
    print(f"  OpenAI: [{status}] {msg}")
    if not ok and "not set" not in msg.lower():
        all_ok = False

    # Ollama (optional)
    ok, msg = check_ollama()
    status = "OK" if ok else "SKIP/FAIL"
    print(f"  Ollama: [{status}] {msg}")
    if not ok and "not installed" not in msg.lower():
        all_ok = False

    print()
    if all_ok:
        print("All required checks passed.")
        return 0
    print("Some checks failed or were skipped. CodeQL is required for Phase 2+.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
