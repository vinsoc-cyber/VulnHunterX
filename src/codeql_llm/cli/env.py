"""Environment check command for CodeQL, OpenAI, and Ollama."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def check_codeql(codeql_path: str = "codeql") -> tuple[bool, str]:
    """
    Verify CodeQL CLI is available and report version.
    
    Args:
        codeql_path: Path to CodeQL executable
        
    Returns:
        Tuple of (success, message)
    """
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


def check_openai(api_key: Optional[str] = None) -> tuple[bool, str]:
    """
    Verify OpenAI API via LiteLLM.
    
    Args:
        api_key: OpenAI API key (defaults to env var)
        
    Returns:
        Tuple of (success, message)
    """
    api_key = api_key or os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return False, "OPENAI_API_KEY not set"
    
    try:
        import litellm
    except ImportError:
        return False, "litellm not installed; run: pip install litellm"
    
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


def check_ollama(
    model: Optional[str] = None,
    api_base: Optional[str] = None,
) -> tuple[bool, str]:
    """
    Verify Ollama via LiteLLM.
    
    Args:
        model: Ollama model name
        api_base: Ollama server URL
        
    Returns:
        Tuple of (success, message)
    """
    try:
        import litellm
    except ImportError:
        return False, "litellm not installed; run: pip install litellm"
    
    model = model or os.environ.get("OLLAMA_MODEL", "ollama/llama3.2")
    if not model.startswith("ollama/"):
        model = f"ollama/{model}"
    
    api_base = api_base or os.environ.get("OLLAMA_API_BASE") or os.environ.get("OLLAMA_BASE_URL") or ""
    api_base = api_base.strip() or None
    
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


def run_env_check(quiet: bool = False) -> dict[str, tuple[bool, str]]:
    """
    Run all environment checks.
    
    Args:
        quiet: Suppress output
        
    Returns:
        Dict mapping check name to (success, message)
    """
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    
    results: dict[str, tuple[bool, str]] = {}
    
    if not quiet:
        print("Environment Check (CodeQL + LLM)\n")
    
    # CodeQL
    ok, msg = check_codeql(codeql_path)
    results["codeql"] = (ok, msg)
    if not quiet:
        status = "OK" if ok else "FAIL"
        print(f"  CodeQL: [{status}] {msg}")
    
    # OpenAI
    ok, msg = check_openai()
    results["openai"] = (ok, msg)
    if not quiet:
        status = "OK" if ok else "SKIP/FAIL"
        print(f"  OpenAI: [{status}] {msg}")
    
    # Ollama
    ok, msg = check_ollama()
    results["ollama"] = (ok, msg)
    if not quiet:
        status = "OK" if ok else "SKIP/FAIL"
        print(f"  Ollama: [{status}] {msg}")
    
    if not quiet:
        print()
    
    return results
