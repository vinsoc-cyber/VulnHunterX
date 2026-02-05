# CodeQLxLLM

**CodeQL + LLM Bug Verification Framework**

A Python framework that combines CodeQL static analysis with Large Language Model (LLM) verification to reduce false positives in security findings. Implements the Vulnhalla methodology for intelligent, multi-turn bug confirmation.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Pipeline Stages](#pipeline-stages)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Verification Modes](#verification-modes)
- [Python API](#python-api)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [References](#references)

---

## Overview

### The Problem

Static analysis tools like CodeQL produce many findings, but a significant portion are **false positives**. Security teams spend considerable time manually reviewing each finding to determine if it's a real vulnerability.

### The Solution

This framework automates the triage process by using LLMs to:

1. **Analyze code context** around each finding
2. **Answer guided questions** specific to each vulnerability type
3. **Request additional context** when needed (multi-turn)
4. **Provide verdicts** with confidence levels and reasoning

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-language Support** | C, C++, Python, JavaScript |
| **Two Verification Modes** | Simple (fast) and Vulnhalla (accurate) |
| **Guided Questions** | Rule-specific questions for structured analysis |
| **Context Expansion** | LLM can request callers, structs, globals |
| **Multiple LLM Providers** | OpenAI (GPT-4) and Ollama (local models) |
| **Unified CLI** | Single command-line tool for entire workflow |
| **Python API** | Programmatic access for integration |

---

## How It Works

### End-to-End Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CodeQL + LLM VERIFICATION PIPELINE                  │
└─────────────────────────────────────────────────────────────────────────────┘

     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
     │   SOURCE     │     │   CODEQL     │     │    SARIF     │
     │   REPOSITORY │────>│   DATABASE   │────>│   FINDINGS   │
     │   (GitHub)   │     │              │     │              │
     └──────────────┘     └──────────────┘     └──────────────┘
            │                    │                    │
     ┌──────┴──────┐      ┌──────┴──────┐      ┌──────┴──────┐
     │  STAGE 1    │      │  STAGE 2    │      │  STAGE 3    │
     │  clone      │      │  analyze    │      │  extract-   │
     │             │      │             │      │  context    │
     └─────────────┘      └─────────────┘      └─────────────┘
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
                         │   │   [Vulnhalla mode only]    │   │
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

### What Makes This Different

**Traditional Approach:**
```
CodeQL Finding -> Manual Review -> Decision
                 (time-consuming)
```

**This Framework:**
```
CodeQL Finding -> Guided Questions -> LLM Analysis -> Verdict
                                      (automated)
```

The **Vulnhalla methodology** (from CyberArk research) enhances this by:
- Using **rule-specific questions** instead of generic prompts
- Allowing **multi-turn conversation** for complex findings
- Enabling **dynamic context expansion** based on LLM requests

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
│          databases/<lang>/<name>/    (CodeQL database)                      │
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
│ Purpose: Run CodeQL security analysis on database                           │
│ Input:   databases/<lang>/<name>/                                           │
│ Output:  output/sarif/<lang>/<name>.sarif                                   │
│                                                                             │
│ This stage:                                                                 │
│   1. Finalizes the database (if not already finalized)                      │
│   2. Runs the security-extended query suite                                 │
│   3. Produces SARIF file with all security findings                         │
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
│ STAGE 3: extract-context (Optional, recommended for Vulnhalla mode)         │
│ ────────────────────────                                                    │
│ Purpose: Pre-extract structured context for multi-turn verification         │
│ Input:   databases/<lang>/<name>/                                           │
│ Output:  output/context/<name>/*.csv                                        │
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
│ Input:   output/sarif/<lang>/<name>.sarif                                   │
│          output/context/<name>/*.csv (for Vulnhalla mode)                   │
│ Output:  output/results/summary_*.json                                      │
│          output/results/details_*.json                                      │
│                                                                             │
│ For each finding:                                                           │
│   1. Extract code context (surrounding lines, enclosing function)           │
│   2. Load guided questions for the rule type                                │
│   3. Build prompt with context and questions                                │
│   4. Send to LLM and parse response                                         │
│   5. [Vulnhalla] If LLM requests more context, fetch and continue           │
│   6. Record verdict with confidence and reasoning                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Stage Input/Output Summary

| Stage | Command | Input | Output |
|-------|---------|-------|--------|
| 1 | `clone` | Repository URL | Source code + CodeQL database |
| 2 | `analyze` | CodeQL database | SARIF file with findings |
| 3 | `extract-context` | CodeQL database | CSV files with context |
| 4 | `verify` | SARIF + CSVs | JSON with verdicts |

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/your-org/CodeQLxLLM.git
cd CodeQLxLLM

uv venv --python python3.12 .venv
source .venv/bin/activate
pip install -e .
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
codeql-llm clone --repo pyyaml
codeql-llm analyze --repo pyyaml
codeql-llm verify --repo pyyaml --limit 5
```

### 4. View Results

```bash
cat output/results/summary_*.json
```

**For detailed setup instructions, see [QUICKSTART.md](QUICKSTART.md)**

---

## CLI Reference

```
codeql-llm <command> [options]
```

### Global Options

| Option | Description |
|--------|-------------|
| `--help` | Show help for command |
| `--version` | Show version |

### check-env

Check that all prerequisites are properly configured.

```bash
codeql-llm check-env
```

**What it checks:**
- CodeQL CLI installed and accessible
- OpenAI API key valid (if configured)
- Ollama server reachable (if configured)

---

### clone

Clone repositories and create CodeQL databases.

```bash
codeql-llm clone [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--repo NAME` | Clone specific repository | All in config |
| `--lang LANG` | Filter by language (c, cpp, python, javascript) | All |
| `--skip-db` | Clone only, don't create database | false |
| `--ask-llm` | Ask LLM for help if build fails | false |
| `--dry-run` | Preview without executing | false |

**Examples:**

```bash
# Clone all repositories
codeql-llm clone

# Clone specific repository
codeql-llm clone --repo libucl

# Clone all C repositories
codeql-llm clone --lang c

# Clone without building database
codeql-llm clone --repo libucl --skip-db
```

---

### analyze

Run CodeQL security analysis on databases.

```bash
codeql-llm analyze [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--repo NAME` | Analyze specific repository | All databases |
| `--lang LANG` | Filter by language | All |
| `-v, --verbose` | Show detailed output | false |
| `--json` | Also output findings as JSON | false |
| `--dry-run` | Preview without executing | false |

**Examples:**

```bash
# Analyze all databases
codeql-llm analyze

# Analyze specific repository with verbose output
codeql-llm analyze --repo libucl -v

# Analyze all C++ databases
codeql-llm analyze --lang cpp
```

**Verbose output includes:**
- Database path and status
- Query suite being used
- Full CodeQL command
- Number of findings detected

---

### extract-context

Extract context CSVs for multi-turn verification.

```bash
codeql-llm extract-context [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--repo NAME` | Extract for specific repository | All databases |
| `--lang LANG` | Filter by language | All |
| `--dry-run` | Preview without executing | false |

**Examples:**

```bash
# Extract context for all databases
codeql-llm extract-context

# Extract for specific repository
codeql-llm extract-context --repo libucl
```

**Output files:**

| File | Description |
|------|-------------|
| `functions.csv` | Function definitions with location and parameters |
| `callers.csv` | Call graph (who calls whom) |
| `structs.csv` | Structure/class definitions |
| `globals.csv` | Global variables |
| `macros.csv` | Macro definitions (C/C++ only) |

---

### verify

Verify CodeQL findings using LLM analysis.

```bash
codeql-llm verify [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--repo NAME` | Verify specific repository | All SARIF files |
| `--lang LANG` | Filter by language | All |
| `--mode MODE` | Verification mode: `simple` or `vulnhalla` | vulnhalla |
| `--provider PROV` | LLM provider: `openai` or `ollama` | From config |
| `--model MODEL` | Model name (e.g., gpt-4o, ollama/llama3.2) | From config |
| `--max-iterations N` | Max conversation rounds (vulnhalla) | 3 |
| `--limit N` | Max findings to process | Unlimited |
| `-v, --verbose` | Show LLM requests and responses | false |
| `-q, --quiet` | Minimal output | false |
| `--log-file PATH` | Save LLM conversations to file | None |

**Examples:**

```bash
# Verify all findings
codeql-llm verify

# Verify specific repository
codeql-llm verify --repo libucl

# Use simple mode (faster)
codeql-llm verify --mode simple

# Use Vulnhalla mode with more iterations
codeql-llm verify --mode vulnhalla --max-iterations 7

# Limit to first 5 findings
codeql-llm verify --limit 5

# Use Ollama instead of OpenAI
codeql-llm verify --provider ollama --model ollama/llama3.2

# Verbose output to see LLM interaction
codeql-llm verify -v

# Save conversations for review
codeql-llm verify --log-file output/conversations.md
```

---

### info

Show current configuration and environment info.

```bash
codeql-llm info
```

---

## Verification Modes

### Simple Mode (`--mode simple`)

Single-shot LLM analysis. Fast but less accurate for complex findings.

```
Finding + Context + Questions  ──>  LLM  ──>  Verdict
         (one request)
```

**Characteristics:**
- 1 API call per finding
- No context expansion
- Best for: Simple, localized issues

### Vulnhalla Mode (`--mode vulnhalla`)

Multi-turn LLM analysis with dynamic context expansion.

```
Finding + Context + Questions  ──>  LLM  ──>  "Need more data"
                                              │
Additional Context (callers, structs)  <──────┘
                                              │
                               LLM  ──>  Final Verdict
```

**Characteristics:**
- Up to N API calls per finding (configurable)
- LLM can request: callers, structs, globals, functions
- Higher accuracy for complex data-flow issues

### Mode Comparison

| Aspect | Simple | Vulnhalla |
|--------|--------|-----------|
| API calls per finding | 1 | 1-7 |
| Context expansion | No | Yes |
| Accuracy | Lower | Higher |
| Speed | Fast | Slower |
| Cost | Low | Higher |
| Best for | Simple issues | Complex data-flow |

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

When using Vulnhalla mode, the LLM can request additional context:

| Request | Format | Description |
|---------|--------|-------------|
| Callers | `caller:function_name` | All functions that call this function |
| Struct | `struct:struct_name` | Structure/class definition |
| Global | `global:variable_name` | Global variable declaration |
| Function | `function:function_name` | Full function definition |

---

## Example Scripts

Ready-to-run pipeline examples:

| Script | Language | Repository |
|--------|----------|------------|
| `examples/pipeline_c.py` | C | libucl |
| `examples/pipeline_cpp.py` | C++ | re2 |
| `examples/pipeline_python.py` | Python | pyyaml |
| `examples/pipeline_javascript.py` | JavaScript | minimist |

All scripts support:

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview without executing |
| `--skip-clone` | Skip clone if exists |
| `--simple` | Use simple mode |
| `--compare` | Compare simple vs vulnhalla |
| `--api` | Use Python API instead of CLI |

```bash
# Example: Compare modes
python examples/pipeline_c.py --compare

# Example: Use API with simple mode
python examples/pipeline_python.py --api --simple
```

---

## Python API

```python
from codeql_llm import VerificationEngine

# Create engine from config
engine = VerificationEngine.from_config("config/confirm_findings.yaml")

# Verify a SARIF file
result = engine.verify_sarif(
    "output/sarif/c/libucl.sarif",
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
from codeql_llm import VerificationEngine
from codeql_llm.core.types import Finding, Verdict

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

| Variable | Description | Required |
|----------|-------------|----------|
| `OPENAI_API_KEY` | OpenAI API key | For OpenAI |
| `OLLAMA_API_BASE` | Ollama server URL | For Ollama |
| `CODEQL_PATH` | Path to CodeQL CLI | If not on PATH |

### Application Settings (`config/confirm_findings.yaml`)

```yaml
# LLM Configuration
provider: openai          # openai or ollama
model: gpt-4o             # Model name
temperature: 0.2          # 0.0-1.0 (lower = more deterministic)
max_tokens: 1500          # Max response length

# Verification Settings
mode: vulnhalla           # simple or vulnhalla
max_iterations: 3         # Max rounds for vulnhalla

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

| Field | Description | Required |
|-------|-------------|----------|
| `name` | Short name for the repository (used in paths) | Yes |
| `url` | Git clone URL | Yes |
| `language` | Programming language: `c`, `cpp`, `python`, `javascript` | Yes |
| `build_command` | Shell command to compile the code | For C/C++ only |

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

### Guided Questions (`config/prompts/guided_questions.yaml`)

Rule-specific questions that force the LLM to reason step-by-step before giving a verdict. Based on the Vulnhalla methodology.

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

| Field | Description |
|-------|-------------|
| `short_description` | Brief explanation of the vulnerability |
| `questions` | List of questions the LLM must answer before verdict |
| `context_hint` | Guidance on what context is important |
| `additional_context` | Context types that may be needed (`caller`, `struct`, `global`) |

**Why guided questions matter:**

Without guided questions, LLMs often pattern-match and produce false verdicts. The questions force the LLM to:
1. Trace variable declarations and values
2. Identify all code paths
3. Check for existing safeguards
4. Reason about the specific code, not generic patterns

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
CodeQLxLLM/
├── src/codeql_llm/           # Framework source code
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
├── databases/                # CodeQL databases
└── output/
    ├── sarif/                # Analysis results
    ├── context/              # Extracted CSVs
    └── results/              # Verification results
```

---

## Guided Questions

Questions are defined per rule type in `config/prompts/guided_questions.yaml`:

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

---

## Security Checks Documentation

- [C/C++ Security Checks](docs/codeql_cpp_security.md)
- [Python Security Checks](docs/codeql_python_security.md)
- [JavaScript Security Checks](docs/codeql_javascript_security.md)

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
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
