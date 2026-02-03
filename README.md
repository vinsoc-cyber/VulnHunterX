# CodeQLxLLM

**CodeQL + LLM Bug Verification Framework**

A Python framework for combining CodeQL static analysis with LLM-based bug verification using guided questions (Vulnhalla methodology).

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Overview

This framework provides:

- **SARIF parsing** for CodeQL findings
- **Context extraction** from source code (heuristic + CSV-based)
- **Guided questions** per rule type for structured reasoning
- **Multi-turn LLM interaction** for context expansion
- **Support for OpenAI and Ollama** via LiteLLM
- **Unified CLI** for the entire workflow

## Quick Start

> **TL;DR**: Get results in 5 minutes with a single command.

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-org/CodeQLxLLM.git
cd CodeQLxLLM

# Create virtual environment and install
uv venv --python python3.12 .venv
source .venv/bin/activate
pip install -e .
```

### 2. Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your OpenAI API key
echo "OPENAI_API_KEY=sk-your-key-here" >> .env
```

### 3. Verify Setup

```bash
codeql-llm check-env
```

You should see green checkmarks for CodeQL and your LLM provider.

### 4. Run Example Pipeline

Use one of the ready-to-run example scripts:

```bash
# C repository (libucl) - full pipeline
python examples/pipeline_c.py

# C++ repository (re2)
python examples/pipeline_cpp.py

# Python repository (pyyaml) - faster, no compilation
python examples/pipeline_python.py

# JavaScript repository (minimist) - known vulnerabilities
python examples/pipeline_javascript.py
```

Or run individual commands:

```bash
# Clone a repository and create CodeQL database
codeql-llm clone --repo libucl

# Run CodeQL security analysis
codeql-llm analyze --repo libucl

# Verify findings with LLM
codeql-llm verify --repo libucl --mode vulnhalla --limit 5
```

### 5. View Results

```bash
# Results are saved to output/results/
ls output/results/

# View the JSON summary
cat output/results/summary_vulnhalla_*.json
```

---

**For detailed documentation, see [QUICKSTART.md](QUICKSTART.md)**

---

## Example Scripts

Ready-to-run pipeline examples for each language:

| Script | Language | Repository | Description |
|--------|----------|------------|-------------|
| `examples/pipeline_c.py` | C | libucl | Full pipeline with CMake build |
| `examples/pipeline_cpp.py` | C++ | re2 | Google RE2 regex library |
| `examples/pipeline_python.py` | Python | pyyaml | No compilation required |
| `examples/pipeline_javascript.py` | JavaScript | minimist | Known prototype pollution |

All scripts support the same options:

```bash
# Basic options
python examples/pipeline_c.py --dry-run     # Preview without executing
python examples/pipeline_c.py --skip-clone  # Skip clone if exists

# Verification mode options
python examples/pipeline_c.py --simple      # Use simple mode (faster, less accurate)
python examples/pipeline_c.py --compare     # Compare simple vs vulnhalla modes

# Python API instead of CLI
python examples/pipeline_c.py --api         # Use Python API
python examples/pipeline_c.py --api --simple  # API with simple mode
```

## CLI Reference

```
codeql-llm <command> [options]

Commands:
  check-env        Check environment (CodeQL, OpenAI, Ollama)
  clone            Clone repos and create CodeQL databases
  analyze          Run CodeQL analysis on databases
  extract-context  Extract context CSVs from databases
  verify           Verify CodeQL findings using LLM
  info             Show configuration and environment info

Common Options (where supported):
  --lang           Filter by language (c, cpp, python, javascript)
  --repo           Filter by repository name
  -v, --verbose    Detailed output (analyze, verify)
  --dry-run        Preview without executing (clone, analyze, extract-context)
  --help           Show command help
```

### check-env

Check that CodeQL CLI and LLM providers are working.

```bash
codeql-llm check-env
```

### clone

Clone repositories and create CodeQL databases.

```bash
# All repos from config
codeql-llm clone

# Specific language
codeql-llm clone --lang c

# Specific repo
codeql-llm clone --repo c-ares

# Skip database creation (clone only)
codeql-llm clone --skip-db

# Ask LLM for build help on failure
codeql-llm clone --ask-llm
```

### analyze

Run CodeQL security analysis on databases.

```bash
# All databases
codeql-llm analyze

# Specific language/repo
codeql-llm analyze --lang c --repo c-ares

# Verbose output (shows commands, paths, status)
codeql-llm analyze --repo c-ares -v

# Also output findings JSON
codeql-llm analyze --json

# Dry run (preview without executing)
codeql-llm analyze --dry-run
```

Verbose mode (`-v`) shows:
- Database path and finalization status
- Query suite being used
- Full CodeQL command being executed
- Number of findings in the output

### extract-context

Extract context CSVs from databases for multi-turn verification.

```bash
# Extract context for all databases
codeql-llm extract-context

# Specific language
codeql-llm extract-context --lang c

# Specific repository
codeql-llm extract-context --repo libucl

# Dry run (preview without executing)
codeql-llm extract-context --dry-run
```

This command runs CodeQL tool queries to pre-extract structured context into CSV files:

| CSV File | Description |
|----------|-------------|
| `functions.csv` | Function definitions with file, start/end lines, parameter count |
| `callers.csv` | Caller-callee relationships between functions |
| `structs.csv` | Structure/class definitions with their fields |
| `globals.csv` | Global variable declarations |
| `macros.csv` | Macro definitions (C/C++ only) |

CSV files are stored in `output/context/<repo>/` and are used by **Vulnhalla mode** to provide additional context when the LLM requests it during multi-turn verification.

**Note:** This step is optional for `--mode simple` but recommended for `--mode vulnhalla`.

### verify

Verify CodeQL findings using LLM.

```bash
# All findings
codeql-llm verify

# Specific repo/language
codeql-llm verify --lang c --repo c-ares

# Use Ollama
codeql-llm verify --provider ollama --model ollama/llama3.2

# Simple mode (single-shot, faster)
codeql-llm verify --mode simple

# Vulnhalla mode (multi-turn, more accurate)
codeql-llm verify --mode vulnhalla --max-iterations 5

# Limit findings and quiet output
codeql-llm verify --limit 10 -q

# Save LLM conversations to file
codeql-llm verify --log-file output/conversations.md
```

## Python API

```python
from codeql_llm import VerificationEngine

# Create engine from config
engine = VerificationEngine.from_config("config/confirm_findings.yaml")

# Verify a SARIF file
result = engine.verify_sarif("output/sarif/c/c-ares.sarif", lang="c", repo_name="c-ares")

# Print results
for verdict in result.verdicts:
    print(f"{verdict.finding.rule_id}: {verdict.verdict} ({verdict.confidence})")
    print(f"  Reasoning: {verdict.reasoning}")

# Save results
engine.save_results(result)
```

### Progress Callbacks

```python
from codeql_llm import VerificationEngine
from codeql_llm.core.types import Finding, Verdict

engine = VerificationEngine.from_config("config/confirm_findings.yaml")

def on_start(i: int, total: int, finding: Finding):
    print(f"[{i}/{total}] Processing {finding.rule_id}...")

def on_complete(i: int, total: int, verdict: Verdict):
    print(f"  -> {verdict.verdict}")

engine.on_finding_start(on_start)
engine.on_finding_complete(on_complete)

result = engine.verify_all_sarif()
```

## Verification Modes

### Simple Mode (`--mode simple`)

Single-shot LLM analysis. Sends finding + context + questions once.

- Faster (single API call)
- No context expansion
- Lower accuracy for complex findings

### Vulnhalla Mode (`--mode vulnhalla`)

Multi-turn LLM analysis with dynamic context expansion.

- Enhanced system prompt forcing step-by-step reasoning
- LLM can request additional context (callers, structs, globals)
- Up to `max_iterations` conversation rounds
- Higher accuracy for complex data-flow issues

## Verification Process

### Flow Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                       VERIFICATION PIPELINE                           │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 1. PARSE SARIF                                                        │
│    - Load CodeQL SARIF file                                           │
│    - Extract findings (rule_id, file, line, message)                  │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 2. LOAD CONTEXT                                                       │
│    - Read source file around the finding location                     │
│    - Extract enclosing function                                       │
│    - Load pre-indexed CSVs (functions, callers, structs, globals)     │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 3. LOAD GUIDED QUESTIONS                                              │
│    - Match rule_id to question template (e.g., cpp/use-after-free)    │
│    - Fall back to generic questions if no specific template           │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 4. BUILD PROMPT                                                       │
│    - System prompt (simple or vulnhalla mode)                         │
│    - User prompt: finding details + code context + guided questions   │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 5. LLM ANALYSIS (Multi-turn for Vulnhalla mode)                       │
│                                                                       │
│    ┌───────────────────────────────────────────────────────────────┐  │
│    │ Iteration 1..N:                                               │  │
│    │   - Send messages to LLM (OpenAI/Ollama via LiteLLM)          │  │
│    │   - Parse JSON response                                       │  │
│    │   - If verdict = "Needs More Data" AND has context_needed:    │  │
│    │       -> Fetch additional context from CSVs                   │  │
│    │       -> Append to conversation                               │  │
│    │       -> Continue to next iteration                           │  │
│    │   - Else: Return final verdict                                │  │
│    └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 6. VERDICT OUTPUT                                                     │
│    - verdict: True Positive | False Positive | Needs More Data        │
│    - confidence: High | Medium | Low                                  │
│    - reasoning: Explanation of the analysis                           │
│    - answers: Responses to each guided question                       │
└───────────────────────────────────────────────────────────────────────┘
```

### LLM Response Format

The LLM returns a structured JSON response:

```json
{
  "answers": [
    "Q1: The buffer is allocated at line 45 with malloc(size)...",
    "Q2: The size comes from user input via argv[1]...",
    "Q3: No bounds checking is performed before the copy..."
  ],
  "verdict": "True Positive",
  "confidence": "High",
  "reasoning": "The buffer overflow is confirmed because...",
  "context_needed": []
}
```

When the LLM needs more context (Vulnhalla mode only):

```json
{
  "answers": ["Partial analysis..."],
  "verdict": "Needs More Data",
  "confidence": "Low",
  "reasoning": "Cannot determine without seeing caller functions",
  "context_needed": ["caller:process_input", "struct:user_data"]
}
```

### Context Types

The LLM can request these context types in `context_needed`:

| Request Format | Description | Example |
|----------------|-------------|---------|
| `caller:<func>` | All callers of a function | `caller:parse_input` |
| `struct:<name>` | Structure definition | `struct:user_data` |
| `global:<name>` | Global variable | `global:config` |
| `function:<name>` | Function definition | `function:validate` |

### Verbose Output

Use `-v` to see the full LLM interaction:

```bash
codeql-llm verify --mode vulnhalla --repo libucl -v
```

This prints:
- System prompt being used
- User prompt with code context and questions
- Raw LLM response
- Parsed verdict and confidence
- Additional context being fetched (if any)

### Saving Conversations

Save full LLM conversations to a markdown file:

```bash
codeql-llm verify --mode vulnhalla --log-file output/conversations.md
```

## Configuration

Configuration is split between environment variables and a YAML config file:

### Environment Variables (`.env`)

For secrets and environment-specific settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key (required for OpenAI) | - |
| `OLLAMA_API_BASE` | Ollama server URL | `http://localhost:11434` |
| `CODEQL_PATH` | Path to CodeQL CLI | `codeql` (on PATH) |

### Application Settings (`config/confirm_findings.yaml`)

```yaml
# LLM provider and model
provider: openai          # openai or ollama
model: gpt-4o             # Model name
temperature: 0.2          # Response temperature (0.0-1.0)
max_tokens: 1500          # Max response tokens

# Verification settings
mode: vulnhalla           # simple or vulnhalla
max_iterations: 3         # Max multi-turn rounds

# Output settings
verbosity: normal         # quiet, normal, or verbose
log_file: null            # Path to save LLM conversations

# Processing limits
limit: 0                  # Max findings (0 = unlimited)
languages: []             # Filter by language
repositories: []          # Filter by repository
```

### Configuration Priority

1. Command-line arguments (highest)
2. Environment variables
3. Config file
4. Built-in defaults (lowest)

## Project Structure

```
CodeQLxLLM/
├── src/codeql_llm/       # Framework package
│   ├── cli/              # CLI commands
│   ├── codeql/           # CodeQL operations
│   ├── context/          # Context extraction
│   ├── core/             # Types and config
│   ├── llm/              # LLM client
│   ├── questions/        # Guided questions
│   ├── sarif/            # SARIF parsing
│   └── verification/     # Verification engine
├── config/               # Configuration (static files)
│   ├── confirm_findings.yaml
│   ├── repos.yaml
│   ├── prompts/          # Guided questions
│   └── queries/          # CodeQL tool queries
├── docs/                 # Documentation
├── examples/             # Usage examples
├── tests/                # Test suite
├── repos/                # Cloned repositories
├── databases/            # CodeQL databases
└── output/               # Generated output
    ├── sarif/            # SARIF files
    ├── context/          # Extracted context CSVs
    └── results/          # Verification results
```

## Guided Questions

Questions are defined in `config/prompts/guided_questions.yaml`:

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

## Security Checks Documentation

- [C/C++ Security Checks](docs/codeql_cpp_security.md)
- [Python Security Checks](docs/codeql_python_security.md)
- [JavaScript Security Checks](docs/codeql_javascript_security.md)

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

## License

MIT License

## References

- [Vulnhalla - CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [LiteLLM](https://github.com/BerriAI/litellm)
