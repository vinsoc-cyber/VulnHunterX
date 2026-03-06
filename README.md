# VulnHunterX

**SAST (CodeQL, Semgrep) + fuzzing + LLM vulnerability hunting and verification**

A Python framework that combines static analysis (CodeQL, Semgrep) with Large Language Model (LLM) verification to reduce false positives in security findings. Implements the Vulnhalla methodology for intelligent, multi-turn bug confirmation.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Pipeline Stages](#pipeline-stages)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Verification Mode](#verification-mode)
- [Python API](#python-api)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [References](#references)

---

## Overview

### The Problem

Static analysis tools like **CodeQL and Semgrep** produce many findings, but a significant portion are **false positives**. Security teams spend considerable time manually reviewing each finding to determine if it's a real vulnerability.

### The Solution

This framework automates the triage process by using LLMs to:

1. **Analyze code context** around each finding
2. **Answer guided questions** specific to each vulnerability type
3. **Request additional context** when needed (multi-turn)
4. **Provide verdicts** with confidence levels and reasoning

### Key Features

| Feature                    | Description                                                                               |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| **Multi-language Support** | C, C++, Python, JavaScript, PHP, Java                                                     |
| **LLM verification**       | Multi-turn with context expansion                                                         |
| **Guided Questions**       | Rule-specific questions for structured analysis                                           |
| **Context Expansion**      | LLM can request callers, structs, globals                                                 |
| **Multiple LLM Providers** | OpenAI (GPT-4), Anthropic (Claude), and Ollama (local models)                             |
| **Dual SAST**              | CodeQL and Semgrep; choose analyzer(s) with `analyze --tool codeql`, `semgrep`, or `both` |
| **Unified CLI**            | Single command-line tool for entire workflow                                              |
| **Python API**             | Programmatic access for integration                                                       |

---

## How It Works

### End-to-End Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  SAST (CodeQL / Semgrep) + LLM VERIFICATION PIPELINE        │
└─────────────────────────────────────────────────────────────────────────────┘

     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
     │   SOURCE     │     │   STATIC     │     │    SARIF     │
     │   REPOSITORY │────>│   ANALYSIS   │────>│   FINDINGS   │
     │   (GitHub)   │     │ (CodeQL/     │     │              │
     └──────────────┘     │  Semgrep)    │     └──────────────┘
            │             └──────────────┘
     ┌──────┴──────┐             │                    │
     │  STAGE 1    │      ┌──────┴──────┐      ┌──────┴──────┐
     │  clone      │      │  STAGE 2    │      │  STAGE 3    │
     │             │      │  analyze    │      │  extract-   │
     └─────────────┘      └─────────────┘      │  context    │
                                               └─────────────┘
                                                      │
                                                      ▼
                         ┌────────────────────────────────────┐
                         │            STAGE 4: verify         │
                         │                                    │
                         │   ┌────────────────────────────┐   │
                         │   │   For each finding:        │   │
                         │   │                            │   │
                         │   │   1. Load code context     │   │
                         │   │   2. Load guided questions │   │
                         │   │   3. Build LLM prompt      │   │
                         │   │   4. Send to LLM           │   │
                         │   │   5. Parse verdict         │   │
                         │   │                            │   │
                         │   │   [LLM mode only]          │   │
                         │   │   6. If needs more data:   │   │
                         │   │      - Fetch context       │   │
                         │   │      - Continue iteration  │   │
                         │   └────────────────────────────┘   │
                         │                                    │
                         └────────────────────────────────────┘
                                          │
                                          ▼
                         ┌────────────────────────────────────┐
                         │           VERIFICATION RESULTS     │
                         │                                    │
                         │   - True Positive (real bug)       │
                         │   - False Positive (not a bug)     │
                         │   - Needs More Data (uncertain)    │
                         │                                    │
                         │   + Confidence: High/Medium/Low    │
                         │   + Reasoning explanation          │
                         │   + Answered guided questions      │
                         └────────────────────────────────────┘
```

The pipeline has four core stages: **clone** (Stage 1) clones the repository and creates a CodeQL database (for compiled languages, this traces the build); **analyze** (Stage 2) runs CodeQL on the database and/or Semgrep on source, producing SARIF; **extract-context** (Stage 3, optional but recommended) pre-extracts structured context (functions, callers, structs) from the CodeQL database into CSV files for multi-turn expansion; **verify** (Stage 4) reads all SARIF files and uses an LLM to confirm or dismiss each finding.

### What Makes This Different

**Traditional Approach:**
```
SAST finding (CodeQL or Semgrep) -> Manual Review -> Decision
                                    (time-consuming)
```

**This Framework:**
```
SAST finding (CodeQL or Semgrep) -> Guided Questions -> LLM Analysis -> Verdict
                                                    (automated)
```

The framework follows the **Vulnhalla methodology** (CyberArk research), which improves accuracy by:
- **Rule-specific questions** — each finding type gets tailored questions instead of a single generic prompt
- **Multi-turn conversation** — the LLM can take several steps to reason about complex data flow
- **Dynamic context expansion** — the LLM can request extra code (callers, structs, globals) before giving a verdict

---

## Pipeline Stages

The framework consists of 4 main stages, each with a dedicated CLI command:

### Stage Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: clone                                                              │
│ ───────────────                                                             │
│ Purpose: Clone source code and create CodeQL database                       │
│ Input:   Repository URL (from config/repos.yaml)                            │
│ Output:  repos/<lang>/<name>/        (source code)                          │
│          output/<lang>/<name>/database/  (CodeQL database)                  │
│                                                                             │
│ CodeQL analysis requires this database; Semgrep does not (it scans the      │
│ repo source).                                                               │
│                                                                             │
│ For compiled languages (C/C++), this stage:                                 │
│   1. Clones the repository                                                  │
│   2. Runs the build command while CodeQL traces the compilation             │
│   3. Creates a CodeQL database from the traced build                        │
│                                                                             │
│ For interpreted languages (Python/JavaScript):                              │
│   1. Clones the repository                                                  │
│   2. Creates database by scanning source files (no build needed)            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STAGE 2: analyze                                                            │
│ ────────────────                                                            │
│ Purpose: Run CodeQL and/or Semgrep security analysis (CodeQL on DB,         │
│          Semgrep on source in repos/)                                       │
│ Input:   output/<lang>/<name>/database/ (CodeQL); repos/<lang>/<name>/      │
│          (Semgrep)                                                          │
│ Output:  output/<lang>/<name>/<name>.sarif (CodeQL); optionally             │
│          <name>_semgrep.sarif (Semgrep)                                     │
│                                                                             │
│ This stage:                                                                 │
│   1. [CodeQL] Finalizes the database (if not already finalized)             │
│   2. [CodeQL] Runs the security-extended query suite                        │
│   3. [Semgrep] Scans source; no database required                           │
│   4. Produces SARIF file(s) with all security findings                      │
│                                                                             │
│ SARIF (Static Analysis Results Interchange Format) contains:                │
│   - Rule ID (e.g., cpp/use-after-free)                                      │
│   - File path and line number                                               │
│   - Message describing the issue                                            │
│   - Severity and other metadata                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STAGE 3: extract-context (Optional, recommended for LLM mode)               │
│ ─────────────────────────────────────────────────────────────────────────── │
│ Purpose: Pre-extract structured context for multi-turn verification         │
│ Input:   output/<lang>/<name>/database/                                     │
│ Output:  output/<lang>/<name>/context/*.csv                                 │
│                                                                             │
│ Uses the CodeQL database; when using Semgrep only, run clone (and           │
│ optionally analyze with CodeQL) if you want full context expansion.         │
│                                                                             │
│ Extracts the following into CSV files:                                      │
│   - functions.csv   : Function definitions (name, file, lines, params)      │
│   - callers.csv     : Caller-callee relationships (call graph)              │
│   - structs.csv     : Structure/class definitions and fields                │
│   - globals.csv     : Global variable declarations                          │
│   - macros.csv      : Macro definitions (C/C++ only)                        │
│                                                                             │
│ Why this matters:                                                           │
│   When the LLM says "I need to see the callers of function X",              │
│   we can quickly look up X in callers.csv instead of re-querying CodeQL.    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STAGE 4: verify                                                             │
│ ───────────────                                                             │
│ Purpose: Verify each finding using LLM analysis                             │
│ Input:   output/<lang>/<name>/*.sarif (CodeQL and Semgrep)                  │
│          output/<lang>/<name>/context/*.csv (for LLM mode)                  │
│ Output:  output/<lang>/<name>/verification_results/*.json                   │
│          output/<lang>/<name>/verification_results/summary_*.json           │
│                                                                             │
│ For each finding:                                                           │
│   1. Extract code context (surrounding lines, enclosing function)           │
│   2. Load guided questions for the rule type                                │
│   3. Build prompt with context and questions                                │
│   4. Send to LLM and parse response                                         │
│   5. [LLM mode] If LLM requests more context, fetch and continue            │
│   6. Record verdict with confidence and reasoning                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Stage Input/Output Summary

| Stage     | Command                 | Input                                   | Output                                              |
| --------- | ----------------------- | --------------------------------------- | --------------------------------------------------- |
| 1         | `clone`                 | Repository URL                          | Source code + CodeQL database                       |
| 2         | `analyze`               | CodeQL database and/or source (Semgrep) | SARIF (e.g. `<name>.sarif`, `<name>_semgrep.sarif`) |
| 3         | `extract-context`       | CodeQL database                         | CSV files with context                              |
| 4         | `verify`                | SARIF + CSVs                            | JSON with verdicts                                  |
| 5 (C/C++) | `build-sanitized`       | Repo + config                           | Sanitized build + manifest                          |
| 6 (C/C++) | `extract-fuzz-context`  | CodeQL DB                               | function_signatures.csv, includes.csv               |
| 7 (C/C++) | `generate-fuzz-drivers` | Verification + context                  | Harness .cc + optional build + status.json          |
| 8 (C/C++) | `fuzz-run`              | Compiled harnesses                      | Crashes + summary.json                              |

See [Fuzz-based confirmation](docs/fuzz_stages.md) for stages 5–8.

VulnHunterX supports **CodeQL** and **Semgrep**. CodeQL requires building a database (stage 1) and runs on that database; Semgrep scans the cloned source and does not need a CodeQL database. You can run one or both; both output SARIF. The verify stage reads all SARIF files and applies the same LLM verification. Context expansion (extract-context) uses the CodeQL database, so for full multi-turn context when using Semgrep, run CodeQL at least once for that repo (e.g. `--tool both`).

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/your-org/VulnHunterX.git
cd VulnHunterX

uv venv --python python3.12 .venv
source .venv/bin/activate
pip install -e .  # use ".[dev]" to also install test/lint tools
```

### 2. Configuration

```bash
cp env.example .env
# Edit .env and add: OPENAI_API_KEY=sk-your-key-here
```

### 3. Run Example Pipeline

```bash
# Full pipeline for Python repository (fastest - no compilation)
python examples/pipeline_python.py

# Or run individual commands:
vuln-hunter-x clone --repo pyyaml
vuln-hunter-x analyze --repo pyyaml
vuln-hunter-x verify --repo pyyaml --limit 5
```

### 4. View Results

```bash
cat output/<lang>/<repo>/verification_results/summary_*.json
```

**For detailed setup instructions, see [QUICKSTART.md](QUICKSTART.md)**

---

## CLI Reference

```
vuln-hunter-x <command> [options]
```

### Global Options

| Option      | Description           |
| ----------- | --------------------- |
| `--help`    | Show help for command |
| `--version` | Show version          |

### check-env

Check that all prerequisites are properly configured.

```bash
vuln-hunter-x check-env
```

**What it checks:**
- CodeQL CLI installed and accessible
- Semgrep CLI (optional; for `analyze --tool semgrep` or `--tool both`)
- OpenAI API key valid (if configured)
- Ollama server reachable (if configured)

---

### clone

Clone repositories and create CodeQL databases.

```bash
vuln-hunter-x clone [options]
```

| Option        | Description                                                | Default       |
| ------------- | ---------------------------------------------------------- | ------------- |
| `--repo NAME` | Clone specific repository                                  | All in config |
| `--lang LANG` | Filter by language (c, cpp, python, javascript, php, java) | All           |
| `--skip-db`   | Clone only, don't create database                          | false         |
| `--ask-llm`   | Ask LLM for help if build fails                            | false         |
| `--dry-run`   | Preview without executing                                  | false         |

**Examples:**

```bash
# Clone all repositories
vuln-hunter-x clone

# Clone specific repository
vuln-hunter-x clone --repo libucl

# Clone all C repositories
vuln-hunter-x clone --lang c

# Clone without building database
vuln-hunter-x clone --repo libucl --skip-db
```

---

### analyze

Run CodeQL and/or Semgrep security analysis. Use `--tool` to choose which analyzer(s) run. Both produce SARIF under `output/<lang>/<repo_name>/`; the verify stage reads all SARIF files (CodeQL and Semgrep).

```bash
vuln-hunter-x analyze [options]
```

| Option                         | Description                                              | Default           |
| ------------------------------ | -------------------------------------------------------- | ----------------- |
| `--tool {codeql,semgrep,both}` | Analyzer(s) to run                                       | codeql            |
| `--semgrep-config CONFIG`      | Semgrep config (repeatable); e.g. auto, p/security-audit | auto              |
| `--codeql-suite SUITE`         | CodeQL query suite (built-in ref or path to .qls)        | language default  |
| `--config PATH`                | Path to repos.yaml (for Semgrep repo list)               | config/repos.yaml |
| `--repo NAME`                  | Analyze specific repository                              | All               |
| `--lang LANG`                  | Filter by language                                       | All               |
| `-v, --verbose`                | Show detailed output                                     | false             |
| `--json`                       | Also output findings as JSON                             | false             |
| `-f, --force`                  | Re-run even if SARIF exists                              | false             |
| `--dry-run`                    | Preview without executing                                | false             |

**Examples:**

```bash
# CodeQL only (default; requires CodeQL DBs from clone)
vuln-hunter-x analyze
vuln-hunter-x analyze --repo libucl -v

# Semgrep only (runs on source in repos/; no CodeQL DB required)
vuln-hunter-x analyze --tool semgrep --repo pyyaml
vuln-hunter-x analyze --tool semgrep --semgrep-config auto --semgrep-config p/security-audit

# Both: CodeQL then Semgrep (both SARIF files per repo)
vuln-hunter-x analyze --tool both --repo c-ares

# Custom CodeQL suite
vuln-hunter-x analyze --codeql-suite path/to/custom.qls
```

**Semgrep integration:** Semgrep runs on the cloned source in `repos/<lang>/<name>/` and writes `output/<lang>/<name>/<name>_semgrep.sarif`. Verify reads all `*.sarif` in each repo directory (CodeQL and Semgrep). Semgrep does not require a CodeQL database.

**Adding more security rules**

- **CodeQL:** Use `--codeql-suite` with a custom `.qls` file that references the standard security-extended suite and adds extra queries or packs. You can also set `codeql_suite` in `config/confirm_findings.yaml`.
- **Semgrep:** Pass multiple `--semgrep-config` (e.g. `auto`, `p/security-audit`, or paths to YAML rule files). Comma-separated in one flag is supported: `--semgrep-config "auto,p/security-audit"`. Optional defaults: `semgrep_configs` or `semgrep_config` in `config/confirm_findings.yaml`.

**Verbose output includes:**
- Database path and status (CodeQL) or repo path (Semgrep)
- Query suite or Semgrep configs
- Number of findings detected

---

### extract-context

Extract context CSVs for multi-turn verification.

```bash
vuln-hunter-x extract-context [options]
```

| Option        | Description                     | Default       |
| ------------- | ------------------------------- | ------------- |
| `--repo NAME` | Extract for specific repository | All databases |
| `--lang LANG` | Filter by language              | All           |
| `--dry-run`   | Preview without executing       | false         |

**Examples:**

```bash
# Extract context for all databases
vuln-hunter-x extract-context

# Extract for specific repository
vuln-hunter-x extract-context --repo libucl
```

**Output files:**

| File            | Description                                       |
| --------------- | ------------------------------------------------- |
| `functions.csv` | Function definitions with location and parameters |
| `callers.csv`   | Call graph (who calls whom)                       |
| `structs.csv`   | Structure/class definitions                       |
| `globals.csv`   | Global variables                                  |
| `macros.csv`    | Macro definitions (C/C++ only)                    |

---

### build-sanitized (Stage 5: fuzz, C/C++ only)

Build repository with sanitizers (ASan/UBSan) in a separate directory for fuzz harness linking. See [docs/fuzz_stages.md](docs/fuzz_stages.md).

```bash
vuln-hunter-x build-sanitized --repo libucl
vuln-hunter-x build-sanitized --lang cpp -f   # Force rebuild
```

| Option           | Description                     |
| ---------------- | ------------------------------- |
| `--repo NAME`    | Build specific repository       |
| `--lang {c,cpp}` | Only C or C++ repos             |
| `-f, --force`    | Rebuild even if manifest exists |
| `--dry-run`      | Preview only                    |

---

### extract-fuzz-context (Stage 6: fuzz, C/C++ only)

Extract fuzz-oriented context (function signatures and includes) from C/C++ CodeQL databases. Writes `output/<lang>/<repo>/context/function_signatures.csv` and `includes.csv` for harness generation. See [docs/fuzz_stages.md](docs/fuzz_stages.md).

```bash
vuln-hunter-x extract-fuzz-context
vuln-hunter-x extract-fuzz-context --repo libucl
vuln-hunter-x extract-fuzz-context --lang cpp --dry-run
```

| Option           | Description          |
| ---------------- | -------------------- |
| `--repo NAME`    | Only this repository |
| `--lang {c,cpp}` | Only this language   |
| `--dry-run`      | Preview only         |

---

### generate-fuzz-drivers (Stage 7.1–7.3: fuzz, C/C++ only)

Generate libFuzzer harness `.cc` files from verified findings (True Positive / Needs More Data by default). Resolves enclosing function from context CSVs and writes one harness per target. See [docs/fuzz_stages.md](docs/fuzz_stages.md).

```bash
vuln-hunter-x generate-fuzz-drivers --repo libucl
vuln-hunter-x generate-fuzz-drivers --verdict tp,nmd   # default
vuln-hunter-x generate-fuzz-drivers --verdict all      # all SARIF findings (no verification filter)
vuln-hunter-x generate-fuzz-drivers --dry-run
```

| Option                   | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| `--repo NAME`            | Only this repository                                      |
| `--lang {c,cpp}`         | Only this language                                        |
| `--verdict FILTER`       | `tp,nmd` (default), `tp`, `nmd`, or `all`                 |
| `--dry-run`              | Do not write .cc files                                    |
| `--build`                | Compile and link harnesses (Stage 7.4); write status.json |
| `--llm-fix`              | Use LLM to fix compile/link errors (Stage 7.5)            |
| `--max-fix-iterations N` | Max LLM fix attempts (default 3)                          |

---

### fuzz-run (Stage 8: optional, C/C++ only)

Run libFuzzer for each compiled harness; collect crashes and write `output/<lang>/<repo>/fuzz_results/summary.json`. See [docs/fuzz_stages.md](docs/fuzz_stages.md).

```bash
vuln-hunter-x fuzz-run
vuln-hunter-x fuzz-run --repo libucl --timeout 120 --max-fuzz-time 60
vuln-hunter-x fuzz-run --dry-run
```

| Option              | Description                                 |
| ------------------- | ------------------------------------------- |
| `--repo NAME`       | Only this repository                        |
| `--timeout N`       | Timeout per harness in seconds (default 60) |
| `--max-fuzz-time N` | libFuzzer `-max_total_time` (default 30)    |
| `--dry-run`         | Do not run fuzzers                          |

---

### verify

Verify findings from SARIF using LLM analysis. Discovers all `*.sarif` under `output/<lang>/<repo_name>/` (CodeQL and Semgrep).

```bash
vuln-hunter-x verify [options]
```

| Option               | Description                                | Default         |
| -------------------- | ------------------------------------------ | --------------- |
| `--repo NAME`        | Verify specific repository                 | All SARIF files |
| `--lang LANG`        | Filter by language                         | All             |
| `--provider PROV`    | LLM provider: `openai` or `ollama`         | From config     |
| `--model MODEL`      | Model name (e.g., gpt-4o, ollama/llama3.2) | From config     |
| `--max-iterations N` | Max conversation rounds (LLM mode)         | 3               |
| `--limit N`          | Max findings to process                    | Unlimited       |
| `-v, --verbose`      | Show LLM requests and responses            | false           |
| `-q, --quiet`        | Minimal output                             | false           |
| `--log-file PATH`    | Save LLM conversations to file             | None            |

**Examples:**

```bash
# Verify all findings
vuln-hunter-x verify

# Verify specific repository
vuln-hunter-x verify --repo libucl

# More conversation rounds (LLM mode)
vuln-hunter-x verify --max-iterations 7

# Limit to first 5 findings
vuln-hunter-x verify --limit 5

# Use Ollama instead of OpenAI
vuln-hunter-x verify --provider ollama --model ollama/llama3.2

# Verbose output to see LLM interaction
vuln-hunter-x verify -v

# Save conversations for review
vuln-hunter-x verify --log-file output/conversations.md
```

---

### info

Show current configuration and environment info.

```bash
vuln-hunter-x info
```

---

## Verification Mode

The framework uses **LLM mode** only: multi-turn LLM analysis with dynamic context expansion. The LLM can request additional context (callers, structs, globals, functions) before giving a verdict, which improves accuracy for complex data-flow issues. The number of conversation rounds per finding is configurable via `--max-iterations` or `max_iterations` in config.

---

## Verification Process Detail

### Flow for Each Finding

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VERIFICATION FLOW (per finding)                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. PARSE FINDING                                                            │
│    - Extract: rule_id, file, line, message                                  │
│    - Example: cpp/use-after-free at src/parser.c:145                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. LOAD CODE CONTEXT                                                        │
│    - Read source file                                                       │
│    - Extract lines around the finding (configurable window)                 │
│    - Identify enclosing function                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. LOAD GUIDED QUESTIONS                                                    │
│    - Match rule_id to question template                                     │
│    - Example for cpp/use-after-free:                                        │
│      Q1: Where is the pointer ALLOCATED?                                    │
│      Q2: Where is the pointer FREED?                                        │
│      Q3: Is the pointer set to NULL after free?                             │
│      Q4: List ALL paths from free() to the flagged use                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. BUILD PROMPT                                                             │
│    - System prompt: Role + instructions + output format                     │
│    - User prompt: Finding details + code + questions                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. LLM ANALYSIS LOOP                                                        │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │ Iteration 1..max_iterations:                                        │  │
│    │                                                                     │  │
│    │   Send prompt to LLM ──────────────────────────────────────────┐    │  │
│    │                                                                │    │  │
│    │   ┌────────────────────────────────────────────────────────────┘    │  │
│    │   │                                                                 │  │
│    │   ▼                                                                 │  │
│    │   Parse JSON response:                                              │  │
│    │   {                                                                 │  │
│    │     "answers": ["Q1: allocated at line 45...", ...],                │  │
│    │     "verdict": "True Positive" | "False Positive" | "Needs Data",   │  │
│    │     "confidence": "High" | "Medium" | "Low",                        │  │
│    │     "reasoning": "The buffer overflow occurs because...",           │  │
│    │     "context_needed": ["caller:parse_input", "struct:user_data"]    │  │
│    │   }                                                                 │  │
│    │                                                                     │  │
│    │   If verdict == "Needs More Data" AND context_needed not empty:     │  │
│    │     - Fetch requested context from CSVs                             │  │
│    │     - Append to conversation history                                │  │
│    │     - Continue to next iteration                                    │  │
│    │   Else:                                                             │  │
│    │     - Return final verdict                                          │  │
│    └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. RECORD RESULT                                                            │
│    - Verdict: True Positive, False Positive, or Needs More Data             │
│    - Confidence: High, Medium, or Low                                       │
│    - Reasoning: Explanation of the analysis                                 │
│    - Answers: Response to each guided question                              │
│    - Iterations: Number of rounds taken                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Context Request Types

When using LLM mode, the LLM can request additional context:

| Request  | Format                   | Description                           |
| -------- | ------------------------ | ------------------------------------- |
| Callers  | `caller:function_name`   | All functions that call this function |
| Struct   | `struct:struct_name`     | Structure/class definition            |
| Global   | `global:variable_name`   | Global variable declaration           |
| Function | `function:function_name` | Full function definition              |

---

## Example Scripts

Ready-to-run pipeline examples:

| Script                            | Language   | Repository |
| --------------------------------- | ---------- | ---------- |
| `examples/pipeline_c.py`          | C          | libucl     |
| `examples/pipeline_cpp.py`        | C++        | re2        |
| `examples/pipeline_python.py`     | Python     | pyyaml     |
| `examples/pipeline_javascript.py` | JavaScript | minimist   |

All scripts support:

| Option         | Description                   |
| -------------- | ----------------------------- |
| `--dry-run`    | Preview without executing     |
| `--skip-clone` | Skip clone if exists          |
| `--api`        | Use Python API instead of CLI |

```bash
# Example: Use Python API
python examples/pipeline_python.py --api
```

---

## Python API

```python
from vuln_hunter_x import VerificationEngine

# Create engine from config
engine = VerificationEngine.from_config("config/confirm_findings.yaml")

# Verify a SARIF file
result = engine.verify_sarif(
    "output/c/libucl/libucl.sarif",
    lang="c",
    repo_name="libucl"
)

# Print results
for verdict in result.verdicts:
    print(f"{verdict.finding.rule_id}: {verdict.verdict}")
    print(f"  Confidence: {verdict.confidence}")
    print(f"  Reasoning: {verdict.reasoning}")

# Save results
engine.save_results(result)
```

### With Progress Callbacks

```python
from vuln_hunter_x import VerificationEngine
from vuln_hunter_x.core.types import Finding, Verdict

engine = VerificationEngine.from_config("config/confirm_findings.yaml")

def on_start(i: int, total: int, finding: Finding):
    print(f"[{i}/{total}] {finding.rule_id} at {finding.location}")

def on_complete(i: int, total: int, verdict: Verdict):
    print(f"  -> {verdict.verdict} ({verdict.confidence})")

engine.on_finding_start(on_start)
engine.on_finding_complete(on_complete)

result = engine.verify_all_sarif()
```

---

## Configuration

### Environment Variables (`.env`)

| Variable            | Description         | Required                              |
| ------------------- | ------------------- | ------------------------------------- |
| `OPENAI_API_KEY`    | OpenAI API key      | For OpenAI                            |
| `ANTHROPIC_API_KEY` | Anthropic API key   | For Claude                            |
| `OLLAMA_API_BASE`   | Ollama server URL   | For Ollama                            |
| `CODEQL_PATH`       | Path to CodeQL CLI  | If not on PATH                        |
| `SEMGREP_PATH`      | Path to Semgrep CLI | If not on PATH (for Semgrep analysis) |

### Application Settings (`config/confirm_findings.yaml`)

```yaml
# LLM Configuration
provider: openai          # openai or ollama
model: gpt-4o             # Model name
temperature: 0.2          # 0.0-1.0 (lower = more deterministic)
max_tokens: 1500          # Max response length

# Verification Settings (LLM mode: multi-turn with context expansion)
max_iterations: 3         # Max conversation rounds per finding

# Output Settings
verbosity: normal         # quiet, normal, verbose
log_file: null            # Path to save conversations

# Processing Limits
limit: 0                  # Max findings (0 = unlimited)
languages: []             # Filter languages
repositories: []          # Filter repositories
```

### Priority Order

1. Command-line arguments (highest)
2. Environment variables
3. Config file
4. Built-in defaults (lowest)

### Repository Definitions (`config/repos.yaml`)

Defines which repositories to clone and analyze:

```yaml
repos:
  # Interpreted language (no build command needed)
  - name: minimist
    url: https://github.com/minimistjs/minimist.git
    language: javascript

  # Compiled language (build command required)
  - name: libucl
    url: https://github.com/vstakhov/libucl.git
    language: c
    build_command: "mkdir -p build && cd build && cmake .. && make"
```

| Field           | Description                                                             | Required       |
| --------------- | ----------------------------------------------------------------------- | -------------- |
| `name`          | Short name for the repository (used in paths)                           | Yes            |
| `url`           | Git clone URL                                                           | Yes            |
| `language`      | Programming language: `c`, `cpp`, `python`, `javascript`, `php`, `java` | Yes            |
| `build_command` | Shell command to compile the code                                       | For C/C++ only |

**Adding a new repository:**

```yaml
# For Python/JavaScript (no compilation)
- name: my-python-app
  url: https://github.com/org/my-python-app.git
  language: python

# For C/C++ (compilation required)
- name: my-c-lib
  url: https://github.com/org/my-c-lib.git
  language: c
  build_command: "make"  # or cmake, autoconf, etc.
```

### Guided Questions (`config/prompts/*_questions.yaml`)

Rule-specific questions that force the LLM to reason step-by-step before giving a verdict. Based on the Vulnhalla methodology (see [References](#references)). Questions are organized into per-language files:

```
config/prompts/
├── system_prompt.yaml        # LLM system prompt template (see below)
├── default_questions.yaml    # Generic fallback for unknown rules
├── cpp_questions.yaml        # C/C++ rules (~52 rules)
├── python_questions.yaml     # Python rules (~55 rules)
├── javascript_questions.yaml # JavaScript rules (~45 rules)
├── php_questions.yaml        # PHP rules (~40 rules)
└── java_questions.yaml       # Java rules (~30 rules)
```

**Example** (from `cpp_questions.yaml`):

```yaml
cpp/use-after-free:
  short_description: "Use of pointer after memory has been freed"
  questions:
    - "Where is the pointer ALLOCATED (malloc, calloc, new)?"
    - "Where is the pointer FREED (free, delete)?"
    - "Is the pointer set to NULL after being freed?"
    - "List ALL paths from free() to the flagged use"
  context_hint: "Must trace all paths between free and use"
  additional_context: ["caller"]
```

| Field                | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `short_description`  | Brief explanation of the vulnerability                          |
| `questions`          | List of questions the LLM must answer before verdict            |
| `context_hint`       | Guidance on what context is important                           |
| `additional_context` | Context types that may be needed (`caller`, `struct`, `global`) |

The loader discovers all `*_questions.yaml` files in `config/prompts/` automatically. If a finding's rule ID is not found, the generic questions from `default_questions.yaml` are used as fallback.

**Why guided questions matter:**

Without guided questions, LLMs often pattern-match and produce false verdicts. The questions force the LLM to:
1. Trace variable declarations and values
2. Identify all code paths
3. Check for existing safeguards
4. Reason about the specific code, not generic patterns

### System Prompt (`config/prompts/system_prompt.yaml`)

The LLM system prompt is loaded from `config/prompts/system_prompt.yaml`. It uses placeholders that are filled at runtime:

| Placeholder   | Filled with                               | Example                     |
| ------------- | ----------------------------------------- | --------------------------- |
| `{tool_name}` | SAST tool that produced the finding       | `CodeQL`, `Semgrep`         |
| `{lang}`      | Programming language of the analyzed code | `c`, `python`, `javascript` |

The prompt instructs the LLM to follow a structured analysis methodology: identify the vulnerability class, answer guided questions with line references, trace data flow from source to sink, evaluate reachability, then provide a verdict.

You can customize this file without modifying Python source code. If the file is missing, a built-in default is used.

### CodeQL Tool Queries (`config/queries/tools/`)

Custom CodeQL queries that extract structured context for multi-turn verification.

```
config/queries/tools/
├── cpp/           # C/C++ queries
│   ├── functions.ql   # Extract function definitions
│   ├── callers.ql     # Extract caller-callee relationships
│   ├── structs.ql     # Extract struct definitions
│   ├── globals.ql     # Extract global variables
│   └── macros.ql      # Extract macro definitions
├── python/        # Python queries
│   ├── functions.ql
│   ├── callers.ql
│   └── classes.ql
└── javascript/    # JavaScript queries
    ├── functions.ql
    ├── callers.ql
    └── classes.ql
```

These queries produce CSV files that enable on-demand context expansion during verification. When the LLM says "I need to see the callers of function X", the framework looks up X in `callers.csv` instead of re-running CodeQL.

**Example query output (callers.csv):**

```csv
callee_name,callee_file,caller_name,caller_file,caller_start_line,caller_end_line
parse_input,src/parser.c,main,src/main.c,45,120
parse_input,src/parser.c,process_file,src/utils.c,78,95
```

---

## Project Structure

```
VulnHunterX/
├── src/vuln_hunter_x/           # Framework source code
│   ├── cli/                  # CLI commands
│   ├── codeql/               # CodeQL operations
│   ├── context/              # Context extraction
│   ├── core/                 # Types and config
│   ├── llm/                  # LLM client
│   ├── questions/            # Guided questions loader
│   ├── sarif/                # SARIF parsing
│   └── verification/         # Verification engine
├── config/
│   ├── confirm_findings.yaml # Main config
│   ├── repos.yaml            # Repository definitions
│   ├── prompts/              # Guided questions
│   └── queries/              # CodeQL tool queries
├── examples/                 # Pipeline examples
├── docs/                     # Security check docs
├── repos/                    # Cloned repositories
└── output/                   # All stage outputs (per lang/repo)
    └── <lang>/<repo_name>/
        ├── database/         # CodeQL database
        ├── <repo_name>.sarif # CodeQL analysis results (and optionally <repo_name>_semgrep.sarif)
        ├── context/          # Extracted CSVs
        ├── verification_results/  # Verification JSONs + summary
        ├── sanitized_build/   # Sanitized build + manifest (C/C++)
        ├── fuzz_targets/      # Harness .cc + status.json (C/C++)
        └── fuzz_results/      # Crashes + summary (C/C++)
```

**Migration from an older layout:** If you previously used top-level `databases/` and `builds/`, move `databases/<lang>/<name>` to `output/<lang>/<name>/database/` and `builds/<lang>/<name>` to `output/<lang>/<name>/sanitized_build/`. Move `output/sarif/<lang>/<name>.sarif` to `output/<lang>/<name>/<name>.sarif`, and `output/context/<name>` to `output/<lang>/<name>/context/`. Verification and fuzz outputs go under `output/<lang>/<name>/verification_results/`, `fuzz_targets/`, and `fuzz_results/`.

---

## Security Checks Documentation

- [C/C++ Security Checks](docs/codeql_cpp_security.md)
- [Python Security Checks](docs/codeql_python_security.md)
- [JavaScript Security Checks](docs/codeql_javascript_security.md)
- **Java:** CodeQL-based analysis (using the default Java query suites) with optional Semgrep rules; a dedicated Java CodeQL security-check doc is not yet available. See [`config/prompts/java_questions.yaml`](config/prompts/java_questions.yaml) for guided verification questions covering ~30 rule types (SQLi, XSS, deserialization, XXE, SSRF, and more).

Findings from Semgrep (SARIF) use the same verification flow; rule IDs may differ (see per-language `*_questions.yaml` files or generic fallback).

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Lint code
ruff check src/

# Type check
mypy src/
```

---

## License

MIT License

---

## References

- [Vulnhalla - CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack) - Original methodology
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
