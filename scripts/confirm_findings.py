#!/usr/bin/env python3
"""
Phase 4: Vulnhalla-Style Confirmation Flow - LLM-based Bug Verification.

For each CodeQL finding in SARIF files, this script:
1. Extracts function context from the source code
2. Loads guided questions for the rule type
3. Sends context + questions to LLM (OpenAI or Ollama via LiteLLM)
4. Saves the verdict (True Positive / False Positive / Needs More Data)

Usage:
  python scripts/confirm_findings.py [--provider openai|ollama] [--model MODEL]
                                     [--sarif PATH] [--repo NAME] [--limit N]
                                     [--dry-run] [--output-dir PATH]

Environment variables:
  OPENAI_API_KEY     - Required for OpenAI provider
  OLLAMA_API_BASE    - Optional, Ollama server URL (default: http://localhost:11434)
  LLM_PROVIDER       - Default provider: openai or ollama
  LLM_MODEL          - Default model (e.g., gpt-4o, ollama/llama3.2)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# Load .env from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
if _REPO_ROOT.joinpath(".env").exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_REPO_ROOT / ".env")
    except ImportError:
        pass

# LiteLLM for unified LLM API
try:
    import litellm
    litellm.set_verbose = False
except ImportError:
    print("Error: litellm not installed. Run: pip install litellm", file=sys.stderr)
    sys.exit(1)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Finding:
    """Represents a single CodeQL finding."""
    rule_id: str
    message: str
    file: str
    start_line: int
    end_line: int
    repo_name: str = ""
    lang: str = ""
    sarif_path: str = ""


@dataclass
class GuidedQuestions:
    """Guided questions template for a rule."""
    rule_id: str
    short_description: str
    questions: list[str]
    context_hint: str


@dataclass
class Verdict:
    """LLM verdict for a finding."""
    finding: Finding
    verdict: str  # "True Positive", "False Positive", "Needs More Data"
    confidence: str  # "High", "Medium", "Low"
    reasoning: str
    answers: list[str]  # Answers to guided questions
    raw_response: str
    model: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    elapsed_seconds: float = 0.0
    context_needed: list[str] = field(default_factory=list)  # ["caller:func", "struct:type"]
    iterations: int = 1  # Number of LLM turns used


# =============================================================================
# Context Extraction (Function Boundaries)
# =============================================================================

class ContextExtractor:
    """
    Extracts function/scope context from source files.
    Uses a heuristic approach to find enclosing function boundaries.
    Includes caching for improved performance when processing multiple findings.
    """

    # Patterns for function definitions by language
    _FUNCTION_PATTERNS: dict[str, list[re.Pattern]] = {
        "c": [
            # C function: type name(params) {
            re.compile(
                r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$',
                re.MULTILINE
            ),
        ],
        "cpp": [
            # C++ function/method
            re.compile(
                r'^[\w\s\*:&<>]+\s+(\w+)\s*\([^)]*\)\s*(?:const|override|final)?\s*\{?\s*$',
                re.MULTILINE
            ),
        ],
        "python": [
            # Python function/method: def name(params):
            re.compile(r'^\s*def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*$', re.MULTILINE),
            # Python async function
            re.compile(r'^\s*async\s+def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*$', re.MULTILINE),
        ],
        "javascript": [
            # JS function declaration
            re.compile(r'^\s*(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{?\s*$', re.MULTILINE),
            # JS arrow function assigned to const/let/var
            re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>', re.MULTILINE),
            # JS method in object/class
            re.compile(r'^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{', re.MULTILINE),
        ],
    }

    def __init__(self, repos_base: Path):
        self.repos_base = repos_base
        # Cache for file contents: {file_path: lines}
        self._file_cache: dict[str, list[str]] = {}
        # Cache for resolved paths: {(file_path, lang): full_path}
        self._path_cache: dict[tuple[str, str], Path | None] = {}
        # Cache for function boundaries: {(file_path, lang): [(start, end, name), ...]}
        self._function_cache: dict[tuple[str, str], list[tuple[int, int, str]]] = {}

    def clear_cache(self) -> None:
        """Clear all caches (useful for testing or memory management)."""
        self._file_cache.clear()
        self._path_cache.clear()
        self._function_cache.clear()

    def get_context(
        self,
        file_path: str,
        line: int,
        lang: str,
        context_lines: int = 50,
    ) -> tuple[str, str, int, int]:
        """
        Extract function context around the given line.
        Uses caching for improved performance on repeated calls.
        
        Returns: (code_context, function_name, start_line, end_line)
        """
        # Resolve file path relative to repos (cached)
        full_path = self._resolve_path(file_path, lang)
        if not full_path or not full_path.is_file():
            # Fallback: return lines around the target
            return self._fallback_context(file_path, line, context_lines)

        # Get file lines (cached)
        lines = self._get_file_lines(full_path)
        if not lines:
            return self._fallback_context(file_path, line, context_lines)

        # Try to find enclosing function
        func_start, func_end, func_name = self._find_function_bounds(
            lines, line - 1, lang  # 0-indexed
        )

        if func_start is not None and func_end is not None:
            context = "\n".join(lines[func_start:func_end + 1])
            return context, func_name or "<anonymous>", func_start + 1, func_end + 1

        # Fallback: context_lines before and after
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        context = "\n".join(lines[start:end])
        return context, "<unknown>", start + 1, end

    def _get_file_lines(self, full_path: Path) -> list[str]:
        """Get file lines with caching."""
        cache_key = str(full_path)
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]
        
        try:
            lines = full_path.read_text(errors="replace").splitlines()
            self._file_cache[cache_key] = lines
            return lines
        except (OSError, UnicodeDecodeError):
            return []

    def _resolve_path(self, file_path: str, lang: str) -> Path | None:
        """Resolve file path to actual location in repos/ (cached)."""
        cache_key = (file_path, lang)
        if cache_key in self._path_cache:
            return self._path_cache[cache_key]
        
        # Try repos/<lang>/*/<file_path>
        lang_dir = self.repos_base / lang
        if lang_dir.is_dir():
            for repo_dir in lang_dir.iterdir():
                candidate = repo_dir / file_path
                if candidate.is_file():
                    self._path_cache[cache_key] = candidate
                    return candidate
        
        self._path_cache[cache_key] = None
        return None

    def _fallback_context(
        self, file_path: str, line: int, context_lines: int
    ) -> tuple[str, str, int, int]:
        """Return a placeholder when file can't be read."""
        return (
            f"[Could not read file: {file_path}]\n[Line {line} flagged]",
            "<unknown>",
            max(1, line - context_lines),
            line + context_lines,
        )

    def _find_function_bounds(
        self, lines: list[str], target_idx: int, lang: str
    ) -> tuple[int | None, int | None, str | None]:
        """
        Find the start and end of the function containing target_idx.
        Returns (start_idx, end_idx, function_name) or (None, None, None).
        """
        patterns = self._FUNCTION_PATTERNS.get(lang, self._FUNCTION_PATTERNS.get("c", []))

        # Search backwards for function start
        func_start = None
        func_name = None
        brace_depth = 0

        for i in range(target_idx, -1, -1):
            line = lines[i]

            # Track braces (rough heuristic)
            brace_depth += line.count('}') - line.count('{')

            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    func_start = i
                    func_name = match.group(1) if match.lastindex else None
                    break

            if func_start is not None:
                break

        if func_start is None:
            return None, None, None

        # Search forward for function end (matching braces)
        brace_depth = 0
        in_function = False
        func_end = None

        for i in range(func_start, len(lines)):
            line = lines[i]
            brace_depth += line.count('{') - line.count('}')

            if '{' in line:
                in_function = True

            if in_function and brace_depth <= 0:
                func_end = i
                break

        # For Python, use indentation
        if lang == "python" and func_end is None:
            base_indent = len(lines[func_start]) - len(lines[func_start].lstrip())
            for i in range(func_start + 1, len(lines)):
                stripped = lines[i].lstrip()
                if stripped and not stripped.startswith('#'):
                    indent = len(lines[i]) - len(stripped)
                    if indent <= base_indent:
                        func_end = i - 1
                        break
            if func_end is None:
                func_end = len(lines) - 1

        return func_start, func_end, func_name


# =============================================================================
# CSV-Based Context Provider (Vulnhalla-style)
# =============================================================================

class ContextProvider:
    """
    Provides additional context on-demand using pre-extracted CSV files.
    
    Supports:
    - caller:function_name - Get the calling function's code
    - struct:type_name - Get struct/class definition
    - global:var_name - Get global variable definition
    - macro:MACRO_NAME - Get macro definition
    """

    def __init__(self, context_dir: Path, repos_dir: Path):
        self.context_dir = context_dir
        self.repos_dir = repos_dir
        self._cache: dict[str, dict] = {}

    def get_additional_context(
        self,
        repo_name: str,
        lang: str,
        context_requests: list[str],
    ) -> dict[str, str]:
        """
        Fetch additional context based on LLM requests.
        
        Args:
            repo_name: Name of the repository
            lang: Language (c, cpp, python, javascript)
            context_requests: List of "type:name" strings (e.g., ["caller:main", "struct:buffer"])
        
        Returns:
            Dict mapping request to code context
        """
        results: dict[str, str] = {}
        
        for request in context_requests:
            if ":" not in request:
                continue
            
            ctx_type, name = request.split(":", 1)
            ctx_type = ctx_type.lower().strip()
            name = name.strip()
            
            if ctx_type == "caller":
                code = self._get_caller_context(repo_name, lang, name)
            elif ctx_type == "struct" or ctx_type == "class":
                code = self._get_struct_context(repo_name, lang, name)
            elif ctx_type == "global":
                code = self._get_global_context(repo_name, lang, name)
            elif ctx_type == "macro":
                code = self._get_macro_context(repo_name, lang, name)
            else:
                code = f"[Unknown context type: {ctx_type}]"
            
            results[request] = code
        
        return results

    def _load_csv(self, repo_name: str, csv_name: str) -> list[dict]:
        """Load a CSV file from the context directory."""
        cache_key = f"{repo_name}/{csv_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        csv_path = self.context_dir / repo_name / f"{csv_name}.csv"
        if not csv_path.is_file():
            return []
        
        try:
            import csv
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self._cache[cache_key] = rows
            return rows
        except Exception:
            return []

    def _read_lines(self, repo_name: str, lang: str, file_path: str, start: int, end: int) -> str:
        """Read specific lines from a source file."""
        # Try to find the file in repos/<lang>/<repo_name>/<file_path>
        full_path = self.repos_dir / lang / repo_name / file_path
        if not full_path.is_file():
            # Try without repo_name in path (some structures differ)
            for repo_dir in (self.repos_dir / lang).iterdir():
                candidate = repo_dir / file_path
                if candidate.is_file():
                    full_path = candidate
                    break
        
        if not full_path.is_file():
            return f"[File not found: {file_path}]"
        
        try:
            lines = full_path.read_text(errors='replace').splitlines()
            # Convert to 0-indexed
            start_idx = max(0, start - 1)
            end_idx = min(len(lines), end)
            return "\n".join(lines[start_idx:end_idx])
        except Exception as e:
            return f"[Error reading file: {e}]"

    def _get_caller_context(self, repo_name: str, lang: str, callee_name: str) -> str:
        """Get the first caller function for the given callee."""
        rows = self._load_csv(repo_name, "callers")
        for row in rows:
            if row.get("callee_name") == callee_name:
                caller_file = row.get("caller_file", "")
                try:
                    start = int(row.get("caller_start_line", 0))
                    end = int(row.get("caller_end_line", 0))
                except ValueError:
                    continue
                if start > 0 and end >= start:
                    code = self._read_lines(repo_name, lang, caller_file, start, end)
                    caller_name = row.get("caller_name", "unknown")
                    return f"// Caller function: {caller_name}\n// File: {caller_file}\n{code}"
        
        return f"[No caller found for: {callee_name}]"

    def _get_struct_context(self, repo_name: str, lang: str, struct_name: str) -> str:
        """Get struct/class definition."""
        csv_name = "classes" if lang in ("python", "javascript") else "structs"
        rows = self._load_csv(repo_name, csv_name)
        for row in rows:
            if row.get("name") == struct_name:
                file_path = row.get("file", "")
                try:
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", 0))
                except ValueError:
                    continue
                if start > 0 and end >= start:
                    code = self._read_lines(repo_name, lang, file_path, start, end)
                    return f"// Struct/Class: {struct_name}\n// File: {file_path}\n{code}"
        
        return f"[Struct/Class not found: {struct_name}]"

    def _get_global_context(self, repo_name: str, lang: str, var_name: str) -> str:
        """Get global variable definition."""
        rows = self._load_csv(repo_name, "globals")
        for row in rows:
            if row.get("name") == var_name:
                file_path = row.get("file", "")
                try:
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", start))
                except ValueError:
                    continue
                var_type = row.get("type", "unknown")
                code = self._read_lines(repo_name, lang, file_path, start, end)
                return f"// Global: {var_name} (type: {var_type})\n// File: {file_path}\n{code}"
        
        return f"[Global variable not found: {var_name}]"

    def _get_macro_context(self, repo_name: str, lang: str, macro_name: str) -> str:
        """Get macro definition."""
        rows = self._load_csv(repo_name, "macros")
        for row in rows:
            if row.get("name") == macro_name:
                file_path = row.get("file", "")
                line = row.get("line", "?")
                body = row.get("body", "")
                return f"// Macro: {macro_name}\n// File: {file_path}:{line}\n#define {macro_name} {body}"
        
        return f"[Macro not found: {macro_name}]"


# =============================================================================
# Guided Questions Loader
# =============================================================================

class QuestionsLoader:
    """Loads and retrieves guided questions for CodeQL rules."""

    def __init__(self, prompts_dir: Path):
        self.questions: dict[str, GuidedQuestions] = {}
        self._load_questions(prompts_dir)

    def _load_questions(self, prompts_dir: Path) -> None:
        """Load all guided questions YAML files."""
        yaml_file = prompts_dir / "guided_questions.yaml"
        if not yaml_file.is_file():
            print(f"Warning: {yaml_file} not found", file=sys.stderr)
            return

        try:
            data = yaml.safe_load(yaml_file.read_text())
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}", file=sys.stderr)
            return

        for rule_id, config in data.items():
            if not isinstance(config, dict):
                continue
            self.questions[rule_id] = GuidedQuestions(
                rule_id=rule_id,
                short_description=config.get("short_description", ""),
                questions=config.get("questions", []),
                context_hint=config.get("context_hint", ""),
            )

    def get_questions(self, rule_id: str) -> GuidedQuestions:
        """Get guided questions for a rule, with fallback to default."""
        # Try exact match
        if rule_id in self.questions:
            return self.questions[rule_id]

        # Try without language prefix (e.g., cpp/sql-injection -> sql-injection)
        short_id = rule_id.split("/")[-1] if "/" in rule_id else rule_id
        for key in self.questions:
            if key.endswith(f"/{short_id}"):
                return self.questions[key]

        # Return default
        return self.questions.get("default", GuidedQuestions(
            rule_id="default",
            short_description="Generic security finding",
            questions=[
                "What is the source of the potentially dangerous data?",
                "How does the data flow to the flagged location?",
                "Are there any validation or sanitization steps?",
                "What is the security impact if exploited?",
            ],
            context_hint="Include the full function context",
        ))


# =============================================================================
# SARIF Parser
# =============================================================================

def parse_sarif(sarif_path: Path, lang: str, repo_name: str) -> list[Finding]:
    """Parse SARIF file and return list of findings."""
    if not sarif_path.is_file():
        return []

    try:
        data = json.loads(sarif_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Failed to parse {sarif_path}: {e}", file=sys.stderr)
        return []

    findings: list[Finding] = []
    runs = data.get("runs") or []

    for run in runs:
        results = run.get("results") or []
        artifacts = {a.get("index"): a for a in (run.get("artifacts") or []) if "index" in a}

        for r in results:
            rule_id = r.get("ruleId") or r.get("rule", {}).get("id") or ""
            msg_obj = r.get("message") or {}
            message = msg_obj.get("text") or msg_obj.get("messageId") or ""

            locs = r.get("locations") or []
            for loc in locs:
                phys = loc.get("physicalLocation") or {}
                art_ref = phys.get("artifactLocation") or {}
                uri = art_ref.get("uri") or ""
                art_index = art_ref.get("index")
                if art_index is not None and art_index in artifacts:
                    uri = artifacts[art_index].get("location", {}).get("uri") or uri

                region = phys.get("region") or {}
                start_line = region.get("startLine") or 0
                end_line = region.get("endLine") or start_line

                findings.append(Finding(
                    rule_id=rule_id,
                    message=message,
                    file=uri,
                    start_line=start_line,
                    end_line=end_line,
                    repo_name=repo_name,
                    lang=lang,
                    sarif_path=str(sarif_path),
                ))

            if not locs:
                findings.append(Finding(
                    rule_id=rule_id,
                    message=message,
                    file="",
                    start_line=0,
                    end_line=0,
                    repo_name=repo_name,
                    lang=lang,
                    sarif_path=str(sarif_path),
                ))

    return findings


def discover_sarif_files(output_dir: Path) -> list[tuple[Path, str, str]]:
    """Discover SARIF files under output/sarif/<lang>/<name>.sarif."""
    sarif_dir = output_dir / "sarif"
    if not sarif_dir.is_dir():
        return []

    results = []
    for lang_dir in sarif_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name
        for sarif_file in lang_dir.glob("*.sarif"):
            repo_name = sarif_file.stem
            results.append((sarif_file, lang, repo_name))
    return results


# =============================================================================
# LLM Integration
# =============================================================================

class LLMClient:
    """Unified LLM client using LiteLLM for OpenAI and Ollama."""

    # Simple mode: Original single-shot prompt (for comparison)
    SIMPLE_SYSTEM_PROMPT = """You are a security static-analysis assistant. Your task is to analyze CodeQL findings and determine if they are real vulnerabilities.

Given:
1. A CodeQL alert (rule, message, file, line)
2. The code context (the function or scope containing the alert)
3. Guided questions to help you reason about the finding

Instructions:
- First, answer each guided question based on the code context
- Then, provide your verdict: "True Positive", "False Positive", or "Needs More Data"
- Explain your reasoning in 1-2 sentences
- Be conservative: if unsure, say "Needs More Data"

Response format (JSON):
{
  "answers": ["answer to Q1", "answer to Q2", ...],
  "verdict": "True Positive" | "False Positive" | "Needs More Data",
  "confidence": "High" | "Medium" | "Low",
  "reasoning": "Brief explanation of your verdict"
}"""

    # Vulnhalla mode: Enhanced prompt forcing step-by-step reasoning
    # with multi-turn context expansion support
    VULNHALLA_SYSTEM_PROMPT = """You are a security static-analysis assistant.

Your task is to determine if a CodeQL finding is a real vulnerability or a false positive.

CRITICAL INSTRUCTIONS:
1. You will receive a CodeQL alert with code context and guided questions.
2. You MUST answer EVERY guided question FIRST, based ONLY on the code shown.
3. ONLY AFTER answering ALL questions, provide your verdict.
4. Do NOT speculate beyond the shown code.
5. Do NOT call something a bug unless the code is CLEARLY unsafe.

Rules for answering questions:
- Trace variable declarations, sizes, and values step by step.
- Note any assignments, reallocations, or changes to values.
- Identify checks, constraints, or sanitization on the data path.
- If you cannot find the answer in the code, say "Not visible in context".

Rules for verdict:
- "True Positive": The code is CLEARLY vulnerable based on the evidence.
- "False Positive": The code is SAFE because of checks, constraints, or context.
- "Needs More Data": You need additional context (caller, struct definition, etc.).

If answering "Needs More Data", specify EXACTLY what context you need:
- "caller:function_name" - need to see the calling function
- "struct:type_name" - need the struct/class definition
- "global:variable_name" - need to see a global variable
- "macro:MACRO_NAME" - need the macro definition

Response format (JSON):
{
  "answers": ["detailed answer to Q1", "detailed answer to Q2", ...],
  "verdict": "True Positive" | "False Positive" | "Needs More Data",
  "confidence": "High" | "Medium" | "Low",
  "reasoning": "1-2 sentence explanation based on your answers",
  "context_needed": ["caller:main", "struct:buffer_t"]  // only if verdict is "Needs More Data"
}"""

    def __init__(
        self,
        provider: str,
        model: str,
        mode: str = "vulnhalla",
        temperature: float = 0.2,
        max_tokens: int = 1500,
    ):
        self.provider = provider
        self.model = model
        self.mode = mode  # "simple" or "vulnhalla"
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Configure Ollama base URL if provided
        if provider == "ollama":
            ollama_base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
            os.environ["OLLAMA_API_BASE"] = ollama_base

    @property
    def system_prompt(self) -> str:
        """Get the system prompt based on mode."""
        if self.mode == "simple":
            return self.SIMPLE_SYSTEM_PROMPT
        return self.VULNHALLA_SYSTEM_PROMPT

    def build_prompt(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
    ) -> str:
        """Build the user prompt for the LLM."""
        questions_text = "\n".join(
            f"{i+1}. {q}" for i, q in enumerate(questions.questions)
        )

        if self.mode == "simple":
            # Simple mode: original prompt style
            return f"""## CodeQL Finding

**Rule**: {finding.rule_id}
**Description**: {questions.short_description}
**Message**: {finding.message}
**File**: {finding.file}
**Line**: {finding.start_line}

## Code Context

Function: `{func_name}`

```
{context}
```

## Guided Questions

{questions_text}

Please analyze this finding. Answer each question, then provide your verdict."""
        else:
            # Vulnhalla mode: forces step-by-step reasoning
            return f"""## CodeQL Finding

**Rule**: {finding.rule_id}
**Description**: {questions.short_description}
**Message**: {finding.message}
**File**: {finding.file}
**Line**: {finding.start_line}

## Code Context

Function: `{func_name}`

```
{context}
```

## Before deciding if this is a real issue, you MUST answer the following questions FIRST:

{questions_text}

---

IMPORTANT: Answer ALL {len(questions.questions)} questions above by examining the code context.
ONLY AFTER answering every question, provide your final verdict in JSON format."""

    def analyze(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        context_provider: "ContextProvider | None" = None,
        max_iterations: int = 3,
        verbose: bool = False,
        log_file: "Any" = None,
        quiet: bool = False,
    ) -> Verdict:
        """
        Send finding to LLM and get verdict.
        
        In 'vulnhalla' mode: Multi-turn support - if the LLM responds with
        "Needs More Data" and specifies context_needed, this method will fetch
        additional context and continue the conversation.
        
        In 'simple' mode: Single-shot only (no multi-turn).
        """
        user_prompt = self.build_prompt(finding, context, questions, func_name)
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        
        # Write to log file if provided
        if log_file:
            log_file.write(f"## Finding: {finding.rule_id}\n\n")
            log_file.write(f"- **File**: `{finding.file}:{finding.start_line}`\n")
            log_file.write(f"- **Message**: {finding.message}\n")
            log_file.write(f"- **Function**: `{func_name}`\n\n")
            log_file.write(f"### System Prompt\n\n```\n{self.system_prompt}\n```\n\n")
            log_file.write(f"### User Prompt\n\n```\n{user_prompt}\n```\n\n")
        
        # In simple mode, disable multi-turn
        if self.mode == "simple":
            max_iterations = 1
            context_provider = None
        
        if verbose:
            print(f"\n    {'─'*56}")
            print(f"    LLM REQUEST DETAILS")
            print(f"    {'─'*56}")
            print(f"    Model: {self.model}")
            print(f"    Mode: {self.mode}")
            print(f"    Temperature: 0.2")
            print(f"    Max tokens: 1500")
            print(f"    System prompt length: {len(self.system_prompt)} chars")
            print(f"    User prompt length: {len(user_prompt)} chars")
            print(f"    Code context length: {len(context)} chars")
            
            print(f"\n    {'─'*56}")
            print(f"    SYSTEM PROMPT")
            print(f"    {'─'*56}")
            # Print system prompt with indentation
            for line in self.system_prompt.splitlines():
                print(f"    | {line}")
            
            print(f"\n    {'─'*56}")
            print(f"    USER PROMPT")
            print(f"    {'─'*56}")
            # Print user prompt with indentation
            for line in user_prompt.splitlines():
                print(f"    | {line}")
            print(f"    {'─'*56}")
        
        start_time = time.time()
        iterations = 0
        all_raw_responses = []
        
        while iterations < max_iterations:
            iterations += 1
            
            if verbose:
                print(f"\n    [Iteration {iterations}/{max_iterations}] Sending request to LLM...")
            elif not quiet:
                # Show minimal progress (not in quiet mode)
                print(f"    Calling LLM...", end="", flush=True)
            
            try:
                response = litellm.completion(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                raw_response = response.choices[0].message.content or ""
                all_raw_responses.append(raw_response)
                
                if not verbose and not quiet:
                    print(f" done ({len(raw_response)} chars)")
                
                # Write to log file
                if log_file:
                    log_file.write(f"### LLM Response (Iteration {iterations})\n\n")
                    log_file.write(f"```json\n{raw_response}\n```\n\n")
                
                if verbose:
                    print(f"\n    {'─'*56}")
                    print(f"    LLM RESPONSE (Iteration {iterations})")
                    print(f"    {'─'*56}")
                    print(f"    Response length: {len(raw_response)} chars")
                    print(f"    ")
                    # Print full response with indentation
                    for line in raw_response.splitlines():
                        print(f"    | {line}")
                    print(f"    {'─'*56}")
                
                # Parse JSON response
                parsed = self._parse_response(raw_response)
                verdict = parsed.get("verdict", "Needs More Data")
                context_needed = parsed.get("context_needed", [])
                
                if verbose:
                    print(f"\n    PARSED RESPONSE:")
                    print(f"      Verdict: {verdict}")
                    print(f"      Confidence: {parsed.get('confidence', 'Unknown')}")
                    print(f"      Reasoning: {parsed.get('reasoning', 'None')[:100]}...")
                    if parsed.get("answers"):
                        print(f"      Answers: {len(parsed.get('answers', []))} answers")
                    if context_needed:
                        print(f"      Context needed: {context_needed}")
                
                # If verdict is final or no context provider, return
                if verdict != "Needs More Data" or not context_needed or not context_provider:
                    elapsed = time.time() - start_time
                    if verbose:
                        print(f"    [Iteration {iterations}] Final verdict reached")
                    
                    # Write final verdict to log file
                    if log_file:
                        log_file.write(f"### Final Verdict\n\n")
                        log_file.write(f"- **Verdict**: {verdict}\n")
                        log_file.write(f"- **Confidence**: {parsed.get('confidence', 'Low')}\n")
                        log_file.write(f"- **Iterations**: {iterations}\n")
                        log_file.write(f"- **Time**: {elapsed:.2f}s\n")
                        log_file.write(f"- **Reasoning**: {parsed.get('reasoning', 'N/A')}\n\n")
                        if parsed.get("answers"):
                            log_file.write(f"**Answers:**\n")
                            for ai, ans in enumerate(parsed.get("answers", []), 1):
                                log_file.write(f"{ai}. {ans}\n")
                            log_file.write(f"\n")
                        log_file.write(f"---\n\n")
                    
                    return Verdict(
                        finding=finding,
                        verdict=verdict,
                        confidence=parsed.get("confidence", "Low"),
                        reasoning=parsed.get("reasoning", "Could not parse response"),
                        answers=parsed.get("answers", []),
                        raw_response="\n---\n".join(all_raw_responses),
                        model=self.model,
                        elapsed_seconds=elapsed,
                        context_needed=context_needed,
                        iterations=iterations,
                    )
                
                # Fetch additional context
                if verbose:
                    print(f"    [Iteration {iterations}] Fetching additional context: {context_needed}")
                
                additional = context_provider.get_additional_context(
                    repo_name=finding.repo_name,
                    lang=finding.lang,
                    context_requests=context_needed,
                )
                
                if verbose:
                    print(f"\n    ADDITIONAL CONTEXT FETCHED:")
                    for req, code in additional.items():
                        code_lines = len(code.splitlines())
                        print(f"      {req}: {len(code)} chars, {code_lines} lines")
                
                if not additional:
                    # No additional context available, return current result
                    elapsed = time.time() - start_time
                    if verbose:
                        print(f"    No additional context found in CSV files")
                        print(f"    Returning current verdict: {verdict}")
                    return Verdict(
                        finding=finding,
                        verdict=verdict,
                        confidence=parsed.get("confidence", "Low"),
                        reasoning=parsed.get("reasoning", "") + " [No additional context available]",
                        answers=parsed.get("answers", []),
                        raw_response="\n---\n".join(all_raw_responses),
                        model=self.model,
                        elapsed_seconds=elapsed,
                        context_needed=context_needed,
                        iterations=iterations,
                    )
                
                # Build follow-up message with additional context
                additional_text = "\n\n".join(
                    f"### {req}\n```\n{code}\n```"
                    for req, code in additional.items()
                )
                follow_up = f"""Here is the additional context you requested:

{additional_text}

Now, please re-analyze the finding with this additional context and provide your final verdict in JSON format."""
                
                if verbose:
                    print(f"\n    {'─'*56}")
                    print(f"    FOLLOW-UP PROMPT (Iteration {iterations} -> {iterations+1})")
                    print(f"    {'─'*56}")
                    for line in follow_up.splitlines():
                        print(f"    | {line}")
                    print(f"    {'─'*56}")
                
                # Write follow-up to log file
                if log_file:
                    log_file.write(f"### Follow-up Prompt (Iteration {iterations} -> {iterations+1})\n\n")
                    log_file.write(f"```\n{follow_up}\n```\n\n")
                
                # Add assistant response and follow-up to conversation
                messages.append({"role": "assistant", "content": raw_response})
                messages.append({"role": "user", "content": follow_up})
                
            except Exception as e:
                elapsed = time.time() - start_time
                if verbose:
                    print(f"    [Iteration {iterations}] ERROR: {e}")
                return Verdict(
                    finding=finding,
                    verdict="Error",
                    confidence="Low",
                    reasoning=f"LLM call failed: {e}",
                    answers=[],
                    raw_response=str(e),
                    model=self.model,
                    elapsed_seconds=elapsed,
                    iterations=iterations,
                )
        
        # Max iterations reached
        elapsed = time.time() - start_time
        if verbose:
            print(f"    Max iterations ({max_iterations}) reached without final verdict")
        return Verdict(
            finding=finding,
            verdict="Needs More Data",
            confidence="Low",
            reasoning=f"Max iterations ({max_iterations}) reached without final verdict",
            answers=[],
            raw_response="\n---\n".join(all_raw_responses),
            model=self.model,
            elapsed_seconds=elapsed,
            iterations=iterations,
        )

    def _parse_response(self, raw: str) -> dict[str, Any]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        # Try to extract JSON from markdown code block
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try direct JSON parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in response
        brace_match = re.search(r'\{.*\}', raw, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        # Manual extraction as fallback
        result = {"answers": [], "verdict": "Needs More Data", "confidence": "Low", "reasoning": ""}

        # Try to extract verdict
        for v in ["True Positive", "False Positive", "Needs More Data"]:
            if v.lower() in raw.lower():
                result["verdict"] = v
                break

        # Try to extract confidence
        for c in ["High", "Medium", "Low"]:
            if f'confidence": "{c}' in raw or f'confidence":"{c}' in raw or f"confidence: {c}" in raw.lower():
                result["confidence"] = c
                break

        result["reasoning"] = raw[:500]  # First 500 chars as reasoning
        return result


# =============================================================================
# Configuration Loading
# =============================================================================

def load_config(config_path: Path) -> dict:
    """Load configuration from YAML file."""
    if not config_path.is_file():
        return {}
    try:
        return yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return {}


# =============================================================================
# Main Script
# =============================================================================

def main() -> int:
    # Load config file first (can be overridden by CLI args)
    config_file = _REPO_ROOT / "config" / "confirm_findings.yaml"
    config = load_config(config_file)
    
    parser = argparse.ArgumentParser(
        description="Phase 4: Vulnhalla-Style LLM Bug Verification",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=config_file,
        help="Path to configuration file (default: config/confirm_findings.yaml)",
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "ollama"],
        default=os.environ.get("LLM_PROVIDER", config.get("provider", "openai")),
        help="LLM provider (default: from config or 'openai')",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("LLM_MODEL", config.get("model")),
        help="LLM model (default: from config or gpt-4o/ollama/llama3.2)",
    )
    parser.add_argument(
        "--sarif",
        type=Path,
        help="Specific SARIF file to process (instead of auto-discovery)",
    )
    parser.add_argument(
        "--repo",
        metavar="NAME",
        help="Only process findings from this repo",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript"],
        help="Only process findings of this language",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=config.get("limit", 0),
        help="Maximum number of findings to process (0 = all)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / config.get("output_dir", "output"),
        help="Base output directory",
    )
    parser.add_argument(
        "--repos-dir",
        type=Path,
        default=_REPO_ROOT / config.get("repos_dir", "repos"),
        help="Base repos directory for context extraction",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without calling LLM",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Minimal output (only verdicts and summary, hide LLM details)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output including full LLM prompts and responses",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=config.get("log_file"),
        help="Save full LLM conversations to a log file (markdown format)",
    )
    parser.add_argument(
        "--mode",
        choices=["simple", "vulnhalla"],
        default=config.get("mode", "vulnhalla"),
        help="Confirmation mode: 'simple' (single-shot, original) or 'vulnhalla' (multi-turn, enhanced)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=config.get("max_iterations", 3),
        help="Maximum LLM conversation rounds for context expansion (default: 3, vulnhalla mode only)",
    )
    parser.add_argument(
        "--context-dir",
        type=Path,
        default=_REPO_ROOT / config.get("context_dir", "config/context"),
        help="Directory containing pre-extracted context CSV files",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=config.get("temperature", 0.2),
        help="LLM temperature (0.0 = deterministic, 1.0 = creative)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=config.get("max_tokens", 1500),
        help="Maximum tokens in LLM response",
    )
    args = parser.parse_args()
    
    # Reload config if a different config file was specified
    if args.config != config_file:
        config = load_config(args.config)

    # Set default model based on provider
    if not args.model:
        args.model = "gpt-4o" if args.provider == "openai" else "ollama/llama3.2"

    # Validate API keys
    if args.provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not set", file=sys.stderr)
        return 1

    # Quiet mode suppresses detailed output
    quiet = args.quiet
    
    if not quiet:
        print(f"Phase 4: LLM Bug Verification")
        print(f"Mode: {args.mode} ({'multi-turn with enhanced prompts' if args.mode == 'vulnhalla' else 'single-shot, original prompts'})")
        print(f"Provider: {args.provider}, Model: {args.model}")
        print(f"Temperature: {args.temperature}, Max tokens: {args.max_tokens}")
        if args.mode == "vulnhalla":
            print(f"Max iterations: {args.max_iterations}")
        print()

    # Load guided questions
    prompts_dir = _REPO_ROOT / "data" / "prompts"
    questions_loader = QuestionsLoader(prompts_dir)
    if not quiet:
        print(f"Loaded {len(questions_loader.questions)} guided question templates")

    # Initialize context extractor (heuristic-based)
    context_extractor = ContextExtractor(args.repos_dir)
    
    # Initialize context provider (CSV-based for multi-turn, vulnhalla mode only)
    context_provider = None
    if args.mode == "vulnhalla":
        context_provider = ContextProvider(args.context_dir, args.repos_dir)
        if not quiet:
            if args.context_dir.is_dir():
                print(f"Context CSV directory: {args.context_dir}")
            else:
                print("Note: No pre-extracted context CSV files found. Run extract_context.py for multi-turn support.")

    # Discover SARIF files
    if args.sarif:
        sarif_files = [(args.sarif, args.lang or "c", args.sarif.stem)]
    else:
        sarif_files = discover_sarif_files(args.output_dir)

    if args.lang:
        sarif_files = [(p, l, n) for p, l, n in sarif_files if l == args.lang]
    if args.repo:
        sarif_files = [(p, l, n) for p, l, n in sarif_files if n.lower() == args.repo.lower()]

    if not sarif_files:
        print("No SARIF files found. Run Phase 3 first (run_codeql_analysis.py).", file=sys.stderr)
        return 1

    if not quiet:
        print(f"Found {len(sarif_files)} SARIF file(s)")

    # Collect all findings
    all_findings: list[Finding] = []
    for sarif_path, lang, repo_name in sarif_files:
        findings = parse_sarif(sarif_path, lang, repo_name)
        all_findings.extend(findings)
        if findings and not quiet:
            print(f"  [{repo_name}] {len(findings)} finding(s)")

    if not all_findings:
        print("\nNo findings in SARIF files. Nothing to verify.", file=sys.stderr)
        return 0

    # Apply limit
    if args.limit > 0:
        all_findings = all_findings[:args.limit]

    if not quiet:
        print(f"\nProcessing {len(all_findings)} finding(s)...")

    if args.dry_run:
        if quiet:
            # Quiet dry-run: just list findings
            print("[DRY RUN]")
            for i, f in enumerate(all_findings, 1):
                print(f"[{i}/{len(all_findings)}] {f.rule_id} @ {f.file}:{f.start_line}")
            print(f"\n{len(all_findings)} finding(s) would be processed.")
        else:
            print("\n" + "="*60)
            print("[DRY RUN - not calling LLM]")
            print("="*60)
            for i, f in enumerate(all_findings, 1):
                questions = questions_loader.get_questions(f.rule_id)
                context, func_name, ctx_start, ctx_end = context_extractor.get_context(
                    f.file, f.start_line, f.lang
                )
                context_lines = len(context.splitlines())
                
                print(f"\n{'─'*60}")
                print(f"[{i}/{len(all_findings)}] {f.rule_id}")
                print(f"{'─'*60}")
                print(f"  Repository: {f.repo_name} ({f.lang})")
                print(f"  File: {f.file}:{f.start_line}")
                print(f"  Message: {f.message[:80]}{'...' if len(f.message) > 80 else ''}")
                print(f"\n  Context extraction:")
                print(f"    Function: {func_name}")
                print(f"    Lines: {ctx_start}-{ctx_end} ({context_lines} lines)")
                print(f"\n  Guided questions ({len(questions.questions)}):")
                print(f"    Rule: {questions.rule_id}")
                print(f"    Description: {questions.short_description}")
                for qi, q in enumerate(questions.questions, 1):
                    print(f"    Q{qi}: {q[:65]}{'...' if len(q) > 65 else ''}")
                
                if args.verbose:
                    print(f"\n  Code context preview (first 8 lines):")
                    for line in context.splitlines()[:8]:
                        print(f"    | {line[:75]}")
                    if context_lines > 8:
                        print(f"    | ... ({context_lines - 8} more lines)")
                        
                print(f"\n  Would call: {args.provider}/{args.model} ({args.mode} mode)")
            
            print(f"\n{'='*60}")
            print(f"Dry run complete. {len(all_findings)} finding(s) would be processed.")
            print(f"{'='*60}")
        return 0

    # Initialize LLM client with selected mode and settings
    llm = LLMClient(
        provider=args.provider,
        model=args.model,
        mode=args.mode,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )

    # Process findings
    results_dir = args.output_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Initialize log file if requested
    log_file = None
    if args.log_file:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(args.log_file, "w", encoding="utf-8")
        log_file.write(f"# LLM Bug Verification Log\n\n")
        log_file.write(f"- **Date**: {datetime.now().isoformat()}\n")
        log_file.write(f"- **Mode**: {args.mode}\n")
        log_file.write(f"- **Provider**: {args.provider}\n")
        log_file.write(f"- **Model**: {args.model}\n")
        log_file.write(f"- **Max Iterations**: {args.max_iterations}\n\n")
        log_file.write(f"---\n\n")
        print(f"Logging to: {args.log_file}")

    verdicts: list[Verdict] = []
    stats = {"True Positive": 0, "False Positive": 0, "Needs More Data": 0, "Error": 0}

    for i, finding in enumerate(all_findings, 1):
        # Quiet mode: minimal output
        if quiet:
            print(f"[{i}/{len(all_findings)}] {finding.rule_id} @ {finding.file}:{finding.start_line}", end="", flush=True)
        else:
            print(f"\n{'='*60}")
            print(f"[{i}/{len(all_findings)}] Analyzing: {finding.rule_id}")
            print(f"{'='*60}")
            print(f"  Repository: {finding.repo_name} ({finding.lang})")
            print(f"  File: {finding.file}")
            print(f"  Line: {finding.start_line}")
            print(f"  Message: {finding.message[:100]}{'...' if len(finding.message) > 100 else ''}")

        # Get guided questions
        questions = questions_loader.get_questions(finding.rule_id)
        if not quiet:
            print(f"\n  [Step 1] Loading guided questions...")
            print(f"    Rule: {questions.rule_id}")
            print(f"    Description: {questions.short_description}")
            print(f"    Questions ({len(questions.questions)}):")
            for qi, q in enumerate(questions.questions, 1):
                print(f"      Q{qi}: {q[:70]}{'...' if len(q) > 70 else ''}")

        # Extract context
        context, func_name, ctx_start, ctx_end = context_extractor.get_context(
            finding.file, finding.start_line, finding.lang
        )
        context_lines = len(context.splitlines())
        if not quiet:
            print(f"\n  [Step 2] Extracting code context...")
            print(f"    Function: {func_name}")
            print(f"    Lines: {ctx_start}-{ctx_end} ({context_lines} lines of context)")
        
        if args.verbose:
            print(f"\n    --- Code Context Preview (first 10 lines) ---")
            for line in context.splitlines()[:10]:
                print(f"    | {line[:80]}")
            if context_lines > 10:
                print(f"    | ... ({context_lines - 10} more lines)")
            print(f"    --- End Preview ---")

        # Call LLM
        if not quiet:
            print(f"\n  [Step 3] Calling LLM ({args.mode} mode)...")
            print(f"    Model: {llm.model}")
            print(f"    Provider: {llm.provider}")
            if args.mode == "vulnhalla":
                print(f"    Max iterations: {args.max_iterations}")
        
        verdict = llm.analyze(
            finding=finding,
            context=context,
            questions=questions,
            func_name=func_name,
            context_provider=context_provider,
            max_iterations=args.max_iterations,
            verbose=args.verbose,
            log_file=log_file,
            quiet=quiet,
        )
        verdicts.append(verdict)

        # Update stats
        stats[verdict.verdict] = stats.get(verdict.verdict, 0) + 1

        # Display result
        if quiet:
            # Quiet mode: just show verdict on same line
            print(f" -> {verdict.verdict} ({verdict.confidence})")
        else:
            print(f"\n  [Step 4] Result")
            print(f"    Verdict: {verdict.verdict}")
            print(f"    Confidence: {verdict.confidence}")
            print(f"    Iterations: {verdict.iterations}")
            print(f"    Time: {verdict.elapsed_seconds:.2f}s")
        
        if not quiet:
            if verdict.answers:
                print(f"    Answers ({len(verdict.answers)}):")
                for ai, a in enumerate(verdict.answers, 1):
                    answer_preview = a[:80] if a else "(empty)"
                    print(f"      A{ai}: {answer_preview}{'...' if len(a) > 80 else ''}")
            
            if verdict.context_needed:
                print(f"    Context requested: {verdict.context_needed}")
            
            print(f"    Reasoning: {verdict.reasoning[:150]}{'...' if len(verdict.reasoning) > 150 else ''}")

        # Save individual result
        result_file = results_dir / finding.lang / finding.repo_name / f"{finding.rule_id.replace('/', '_')}_{finding.start_line}.json"
        result_file.parent.mkdir(parents=True, exist_ok=True)
        result_file.write_text(json.dumps({
            "finding": {
                "rule_id": finding.rule_id,
                "message": finding.message,
                "file": finding.file,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "repo_name": finding.repo_name,
                "lang": finding.lang,
            },
            "mode": args.mode,
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "reasoning": verdict.reasoning,
            "answers": verdict.answers,
            "context_needed": verdict.context_needed,
            "iterations": verdict.iterations,
            "model": verdict.model,
            "timestamp": verdict.timestamp,
            "elapsed_seconds": verdict.elapsed_seconds,
        }, indent=2))

    # Summary
    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  Total findings analyzed: {len(verdicts)}")
    for verdict_type, count in stats.items():
        if count > 0:
            pct = count / len(verdicts) * 100
            print(f"  {verdict_type}: {count} ({pct:.1f}%)")

    # Write summary to log file and close it
    if log_file:
        log_file.write(f"# Summary\n\n")
        log_file.write(f"- **Total findings**: {len(verdicts)}\n")
        for verdict_type, count in stats.items():
            if count > 0:
                pct = count / len(verdicts) * 100
                log_file.write(f"- **{verdict_type}**: {count} ({pct:.1f}%)\n")
        log_file.close()
        print(f"\nLog saved to: {args.log_file}")

    # Save summary
    summary_file = results_dir / f"summary_{args.mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    summary_file.write_text(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "mode": args.mode,
        "provider": args.provider,
        "model": args.model,
        "max_iterations": args.max_iterations if args.mode == "vulnhalla" else 1,
        "total_findings": len(verdicts),
        "stats": stats,
        "verdicts": [
            {
                "rule_id": v.finding.rule_id,
                "file": v.finding.file,
                "line": v.finding.start_line,
                "verdict": v.verdict,
                "confidence": v.confidence,
                "reasoning": v.reasoning,
                "iterations": v.iterations,
            }
            for v in verdicts
        ],
    }, indent=2))
    print(f"Summary saved to: {summary_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
