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

### Installation

```bash
# Create venv and install
uv venv --python python3.12 .venv
source .venv/bin/activate
pip install -e .
```

### Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required for OpenAI
OPENAI_API_KEY=sk-...

# Optional: Ollama server URL (default: http://localhost:11434)
OLLAMA_API_BASE=http://remote-server:11434

# Optional: Default provider and model
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
```

### Run the Full Pipeline

```bash
# 1. Check environment
codeql-llm check-env

# 2. Clone repos and create CodeQL databases
codeql-llm clone --lang c

# 3. Run CodeQL analysis
codeql-llm analyze --lang c

# 4. Extract context CSVs (for multi-turn mode)
codeql-llm extract-context --lang c

# 5. Verify findings with LLM
codeql-llm verify --lang c --repo c-ares
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

# Also output findings JSON
codeql-llm analyze --json
```

### extract-context

Extract context CSVs from databases for multi-turn verification.

```bash
codeql-llm extract-context --lang c
```

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

## Configuration

`config/confirm_findings.yaml`:

```yaml
# LLM settings
provider: openai          # openai or ollama
model: gpt-4o             # Model name
temperature: 0.2          # Response temperature
max_tokens: 1500          # Max response tokens

# Verification settings
mode: vulnhalla           # simple or vulnhalla
max_iterations: 3         # Max multi-turn rounds

# Output settings
verbosity: normal         # quiet, normal, or verbose
```

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
├── config/               # Configuration
│   ├── confirm_findings.yaml
│   ├── repos.yaml
│   ├── prompts/          # Guided questions
│   ├── queries/          # CodeQL tool queries
│   └── context/          # Pre-extracted CSVs
├── docs/                 # Documentation
├── examples/             # Usage examples
├── tests/                # Test suite
├── repos/                # Cloned repositories
├── databases/            # CodeQL databases
└── output/               # Analysis results
    ├── sarif/            # SARIF files
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
