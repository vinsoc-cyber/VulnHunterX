"""Environment check command for CodeQL, OpenAI, and Ollama."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import yaml


def load_config_for_check() -> dict:
    """Load config from confirm_findings.yaml for environment checks."""
    config_path = Path.cwd() / "config" / "confirm_findings.yaml"
    if not config_path.is_file():
        return {}
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


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


def check_openai(api_key: str | None = None, model: str | None = None) -> tuple[bool, str]:
    """
    Verify OpenAI API via LiteLLM.
    
    Args:
        api_key: OpenAI API key (defaults to env var)
        model: Model name to test (defaults to gpt-4o-mini)
        
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
    
    # Use provided model, or default to gpt-4o-mini for testing
    model = model or "gpt-4o-mini"

    # Custom base URL for OpenAI-compatible endpoints (e.g. Z.ai)
    api_base = (os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE") or "").strip()
    api_base = api_base.rstrip("/") if api_base else None
    if api_base and not model.startswith("openai/"):
        model = "openai/" + model

    try:
        kwargs = {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
            "api_key": api_key,
            "max_tokens": 10,
        }
        if api_base:
            kwargs["api_base"] = api_base
        resp = litellm.completion(**kwargs)
        text = (resp.choices[0].message.content or "").strip()
        return True, f"OpenAI ({model}): {text[:50]}"
    except Exception as e:
        return False, f"OpenAI error: {e}"


def check_ollama(
    model: str | None = None,
    api_base: str | None = None,
) -> tuple[bool, str]:
    """
    Verify Ollama via LiteLLM.
    
    Args:
        model: Ollama model name (from config)
        api_base: Ollama server URL (from env)
        
    Returns:
        Tuple of (success, message)
    """
    try:
        import litellm
    except ImportError:
        return False, "litellm not installed; run: pip install litellm"
    
    # Model comes from config, api_base from environment
    if not model:
        return False, "No Ollama model configured"
    
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
    
    Loads model/provider from env (LLM_PROVIDER, LLM_MODEL) or config file.
    Loads secrets (API keys, URLs) from environment variables.
    
    Args:
        quiet: Suppress output
        
    Returns:
        Dict mapping check name to (success, message)
    """
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    
    # Load config for model/provider (env overrides config file)
    config = load_config_for_check()
    provider = os.environ.get("LLM_PROVIDER") or config.get("provider", "openai")
    model = os.environ.get("LLM_MODEL") or config.get("model", "gpt-4o")
    
    results: dict[str, tuple[bool, str]] = {}
    
    if not quiet:
        print("Environment Check (CodeQL + LLM)\n")
        print(f"  Provider/Model: {provider}, {model}\n")
    
    # CodeQL
    ok, msg = check_codeql(codeql_path)
    results["codeql"] = (ok, msg)
    if not quiet:
        status = "OK" if ok else "FAIL"
        print(f"  CodeQL: [{status}] {msg}")
    
    # OpenAI - test if provider is openai or if we have an API key
    if provider == "openai" or os.environ.get("OPENAI_API_KEY"):
        openai_model = model if provider == "openai" and not model.startswith("ollama/") else None
        ok, msg = check_openai(model=openai_model)
        results["openai"] = (ok, msg)
        if not quiet:
            status = "OK" if ok else "SKIP/FAIL"
            print(f"  OpenAI: [{status}] {msg}")
    else:
        results["openai"] = (False, "Not configured")
        if not quiet:
            print("  OpenAI: [SKIP] Not configured")
    
    # Ollama - test if provider is ollama or model starts with ollama/
    if provider == "ollama" or model.startswith("ollama/"):
        ollama_model = model if model.startswith("ollama/") else f"ollama/{model}"
        ok, msg = check_ollama(model=ollama_model)
        results["ollama"] = (ok, msg)
        if not quiet:
            status = "OK" if ok else "SKIP/FAIL"
            print(f"  Ollama: [{status}] {msg}")
    else:
        results["ollama"] = (False, "Not configured")
        if not quiet:
            print("  Ollama: [SKIP] Not configured")
    
    if not quiet:
        print()
    
    return results
