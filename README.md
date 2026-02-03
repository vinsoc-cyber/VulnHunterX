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
- **CLI and Python API** for flexible usage

See [the plan](.cursor/plans/codeql_llm_bug_verification_demo_692ae989.plan.md) for full phases.

## Quick Start

### Installation

```bash
# Create venv and install deps
uv venv --python python3.12 .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows

# Install in development mode
uv pip install -e .

# Or with pip
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

### Run Verification

```bash
# Using CLI
codeql-llm verify --lang c --repo c-ares

# Using script
python scripts/confirm_findings.py --lang c --repo c-ares

# Dry run to see what would be processed
codeql-llm verify --dry-run
```

## Framework Architecture

```
src/codeql_llm/
├── __init__.py           # Package exports
├── core/
│   ├── types.py          # Finding, Verdict, GuidedQuestions dataclasses
│   └── config.py         # Configuration management
├── sarif/
│   └── parser.py         # SARIF file parsing
├── context/
│   ├── extractor.py      # Heuristic-based context extraction
│   └── provider.py       # CSV-based context lookup
├── questions/
│   └── loader.py         # Guided questions loading
├── llm/
│   ├── prompts.py        # Prompt templates
│   └── client.py         # LLM client (OpenAI/Ollama)
├── verification/
│   └── engine.py         # Main verification orchestrator
├── codeql/
│   ├── database.py       # Database creation/management
│   └── analysis.py       # Running CodeQL queries
└── cli/
    └── main.py           # Command-line interface
```

## Python API

### Basic Usage

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

### Custom Configuration

```python
from codeql_llm import VerificationEngine
from codeql_llm.core.config import Config

# Create custom config
config = Config.from_dict({
    "provider": "ollama",
    "model": "ollama/llama3.2",
    "mode": "simple",
    "max_iterations": 1,
})

engine = VerificationEngine(config)
result = engine.verify_sarif("output/sarif/c/test.sarif", "c", "test")
```

### Direct Component Usage

```python
from pathlib import Path
from codeql_llm.sarif.parser import parse_sarif_file
from codeql_llm.questions.loader import QuestionsLoader
from codeql_llm.context.extractor import ContextExtractor
from codeql_llm.llm.client import LLMClient

# Parse SARIF
findings = parse_sarif_file(Path("output/sarif/c/test.sarif"), "c", "test")

# Load questions
loader = QuestionsLoader(Path("config/prompts"))
questions = loader.get_questions("cpp/buffer-overflow")

# Extract context
extractor = ContextExtractor(Path("repos"))
context = extractor.get_context(findings[0].file, findings[0].start_line, "c")

# Analyze with LLM
client = LLMClient(provider="openai", model="gpt-4o", mode="vulnhalla")
verdict = client.analyze(
    finding=findings[0],
    context=context.code,
    questions=questions,
    func_name=context.function_name,
)
```

## CLI Reference

```
codeql-llm verify [OPTIONS]

Options:
  --config PATH           Configuration file path
  --provider [openai|ollama]  LLM provider
  --model TEXT            LLM model name
  --mode [simple|vulnhalla]   Verification mode
  --max-iterations INT    Max LLM rounds (vulnhalla mode)
  --sarif PATH            Specific SARIF file to process
  --repo TEXT             Filter by repository name
  --lang [c|cpp|python|javascript]  Filter by language
  --limit INT             Max findings to process
  -q, --quiet             Minimal output
  -v, --verbose           Detailed output with prompts/responses
  --log-file PATH         Save conversations to markdown file
  --dry-run               Show what would be processed
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

## Configuration File

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
log_file: null            # Path to save conversations

# Processing limits
limit: 0                  # 0 = process all findings
languages: []             # Empty = all languages
repositories: []          # Empty = all repos
```

## Project Phases

### Phase 1: Environment Check

Verify CodeQL CLI and LLM providers.

```bash
python scripts/check_env.py
```

### Phase 2: Clone Repos & Create Databases

```bash
# Clone and create DBs for all repos
python scripts/clone_and_db.py

# Only specific language/repo
python scripts/clone_and_db.py --lang c --repo c-ares
```

### Phase 3: Run CodeQL Analysis

```bash
# Analyze all databases
python scripts/run_codeql_analysis.py

# Specific repo
python scripts/run_codeql_analysis.py --repo c-ares
```

### Phase 4: LLM Verification

```bash
# Using CLI
codeql-llm verify

# Using script with options
python scripts/confirm_findings.py \
    --mode vulnhalla \
    --provider openai \
    --limit 10 \
    --verbose
```

### Phase 5: Framework (This README)

The framework is now refactored into a proper Python package.

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

See detailed CodeQL security check documentation:

- [C/C++ Security Checks](docs/codeql_cpp_security.md)
- [Python Security Checks](docs/codeql_python_security.md)
- [JavaScript Security Checks](docs/codeql_javascript_security.md)
- [General Overview](docs/codeql_security_checks.md)

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Lint code
ruff check src/ scripts/

# Type check
mypy src/
```

## Directory Structure

```
CodeQLxLLM/
├── src/codeql_llm/      # Python framework package
├── scripts/             # CLI scripts
├── config/              # Configuration files
│   ├── prompts/         # Guided questions YAML
│   ├── queries/         # CodeQL tool queries
│   └── context/         # Pre-extracted context CSVs
├── repos/               # Cloned repositories
├── databases/           # CodeQL databases
├── output/
│   ├── sarif/           # SARIF analysis results
│   └── results/         # LLM verification results
├── docs/                # Documentation
├── examples/            # Usage examples
└── tests/               # Test suite
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## References

- [Vulnhalla - CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [LiteLLM](https://github.com/BerriAI/litellm)
