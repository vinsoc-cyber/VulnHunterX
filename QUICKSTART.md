# CodeQL + LLM Bug Verification - Quick Start Guide

This guide walks you through setting up and using the CodeQL + LLM Bug Verification framework from scratch.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running Your First Analysis](#running-your-first-analysis)
- [Understanding the Output](#understanding-the-output)
- [Example Pipelines](#example-pipelines)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

### Required

| Tool | Version | Purpose |
|------|---------|---------|
| **Python** | 3.12+ | Runtime environment |
| **CodeQL CLI** | 2.15+ | Static analysis |
| **Git** | Any | Repository cloning |

### LLM Provider (choose one)

| Provider | Requirements |
|----------|--------------|
| **OpenAI** | API key from [platform.openai.com](https://platform.openai.com) |
| **Ollama** | Local installation from [ollama.ai](https://ollama.ai) |

### Verify Prerequisites

```bash
# Check Python version
python3 --version  # Should be 3.12+

# Check CodeQL
codeql version  # Should show version 2.15+

# Check Git
git --version
```

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/vinsoc-cyber/CodeQLxLLM.git
cd CodeQLxLLM
```

### Step 2: Create Virtual Environment

Using `uv` (recommended):

```bash
uv venv --python python3.12 .venv
source .venv/bin/activate
```

Or using standard `venv`:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install the Package

```bash
pip install -e .
```

### Step 4: Install CodeQL Query Packs (Optional)

Required only for `extract-context` command:

```bash
codeql pack install config/queries/tools/cpp
codeql pack install config/queries/tools/python
codeql pack install config/queries/tools/javascript
```

### Step 5: Verify Installation

```bash
codeql-llm --help
```

You should see the CLI help with available commands.

---

## Configuration

### Quick Setup

```bash
# Copy example configuration
cp .env.example .env

# Edit with your API key
nano .env  # or use your preferred editor
```

### Environment Variables (`.env`)

```bash
# =============================================================================
# LLM Provider Credentials
# =============================================================================

# OpenAI API Key (required for OpenAI provider)
OPENAI_API_KEY=sk-your-api-key-here

# Ollama Server URL (optional, defaults to localhost)
OLLAMA_API_BASE=http://localhost:11434

# =============================================================================
# CodeQL Configuration
# =============================================================================

# Path to CodeQL CLI (optional if on PATH)
CODEQL_PATH=codeql
```

### Application Settings (`config/confirm_findings.yaml`)

```yaml
# LLM Provider Configuration
provider: openai          # openai or ollama
model: gpt-4o             # Model to use
temperature: 0.2          # Lower = more deterministic
max_tokens: 1500          # Max response length

# Verification Mode
mode: vulnhalla           # vulnhalla (multi-turn) or simple (single-shot)
max_iterations: 3         # Max rounds for vulnhalla mode

# Output Settings
verbosity: normal         # quiet, normal, or verbose
```

### Verify Configuration

```bash
codeql-llm check-env
```

Expected output:

```
CodeQL + LLM Environment Check
==============================

[OK] CodeQL CLI found: /usr/local/bin/codeql
     Version: 2.15.4
[OK] OpenAI API key configured
[OK] OpenAI connection successful

All checks passed!
```

---

## Running Your First Analysis

### Option A: Use an Example Script (Recommended)

The fastest way to see the framework in action:

```bash
# Run the Python pipeline (fastest - no compilation)
python examples/pipeline_python.py
```

This will:
1. Clone the `pyyaml` repository
2. Create a CodeQL database
3. Run security analysis
4. Extract context for multi-turn verification
5. Verify findings with LLM

### Option B: Run Commands Individually

```bash
# Step 1: Clone a repository and create CodeQL database
codeql-llm clone --repo libucl

# Step 2: Run CodeQL security analysis
codeql-llm analyze --repo libucl -v

# Step 3: Extract context for multi-turn verification (optional)
codeql-llm extract-context --repo libucl

# Step 4: Verify findings with LLM
codeql-llm verify --repo libucl --mode vulnhalla --limit 5 -v
```

### Option C: Dry Run First

Preview what will happen without executing:

```bash
python examples/pipeline_c.py --dry-run
```

---

## Understanding the Output

### SARIF Files

CodeQL analysis produces SARIF files in `output/sarif/<lang>/<repo>.sarif`:

```json
{
  "runs": [{
    "results": [{
      "ruleId": "cpp/use-after-free",
      "message": { "text": "This pointer may be used after being freed" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/parser.c" },
          "region": { "startLine": 145 }
        }
      }]
    }]
  }]
}
```

### Verification Results

Results are saved to `output/results/`:

```
output/results/
├── summary_vulnhalla_20260203_120000.json   # Summary statistics
└── details_vulnhalla_20260203_120000.json   # Full verdict details
```

#### Summary JSON

```json
{
  "mode": "vulnhalla",
  "provider": "openai",
  "model": "gpt-4o",
  "total_findings": 11,
  "stats": {
    "True Positive": 3,
    "False Positive": 5,
    "Needs More Data": 3
  },
  "total_time_seconds": 45.2
}
```

#### Detail JSON

```json
{
  "verdicts": [
    {
      "finding": {
        "rule_id": "cpp/use-after-free",
        "file": "src/parser.c",
        "line": 145,
        "message": "This pointer may be used after being freed"
      },
      "verdict": "True Positive",
      "confidence": "High",
      "reasoning": "The pointer 'buf' is freed at line 140 and then accessed at line 145...",
      "iterations": 2
    }
  ]
}
```

### Context CSVs

Extracted context is stored in `output/context/<repo>/`:

| File | Contents |
|------|----------|
| `functions.csv` | Function definitions with file, line, params |
| `callers.csv` | Caller-callee relationships |
| `structs.csv` | Struct/class definitions |
| `globals.csv` | Global variables |
| `macros.csv` | Macro definitions (C/C++ only) |

---

## Example Pipelines

### C Repository (libucl)

```bash
python examples/pipeline_c.py
```

- Uses CMake for building
- Demonstrates memory safety checks
- Includes buffer overflow detection

### C++ Repository (re2)

```bash
python examples/pipeline_cpp.py
```

Options:

```bash
python examples/pipeline_cpp.py --simple  # Use simple mode (faster)
```

### Python Repository (pyyaml)

```bash
python examples/pipeline_python.py
```

- No compilation required
- Fastest to analyze
- Demonstrates injection vulnerability checks

Options:

```bash
python examples/pipeline_python.py --api  # Use Python API instead of CLI
```

### JavaScript Repository (minimist)

```bash
python examples/pipeline_javascript.py
```

- Known prototype pollution vulnerabilities
- Good for demonstrating security analysis

Options:

```bash
python examples/pipeline_javascript.py --compare  # Compare simple vs vulnhalla
```

---

## Common Workflows

### Analyze All Repositories

```bash
# Clone all repos in config/repos.yaml
codeql-llm clone

# Analyze all databases
codeql-llm analyze

# Verify all findings
codeql-llm verify
```

### Focus on Specific Language

```bash
codeql-llm clone --lang python
codeql-llm analyze --lang python
codeql-llm verify --lang python
```

### Quick Analysis (Simple Mode)

For faster results with lower accuracy:

```bash
codeql-llm verify --mode simple --limit 10
```

### Deep Analysis (Vulnhalla Mode)

For higher accuracy with more LLM calls:

```bash
codeql-llm verify --mode vulnhalla --max-iterations 7 -v
```

### Using Ollama (Local LLM)

```bash
# Start Ollama server (in another terminal)
ollama serve

# Pull a model
ollama pull llama3.2

# Run verification with Ollama
codeql-llm verify --provider ollama --model ollama/llama3.2
```

### Save LLM Conversations

```bash
codeql-llm verify --log-file output/conversations.md
```

---

## Troubleshooting

### CodeQL Not Found

```
[ERROR] CodeQL CLI not found
```

**Solution**: Add CodeQL to your PATH or set `CODEQL_PATH` in `.env`:

```bash
export PATH="$PATH:/path/to/codeql"
# or
echo "CODEQL_PATH=/path/to/codeql/codeql" >> .env
```

### OpenAI API Error

```
[ERROR] OpenAI API key not configured
```

**Solution**: Ensure your API key is set in `.env`:

```bash
echo "OPENAI_API_KEY=sk-your-key-here" >> .env
```

### Database Already Finalized

```
Database is already finalized
```

This is normal - the framework handles this automatically. The analysis will proceed.

### No Findings in SARIF

```
0 findings in SARIF file
```

**Possible causes**:
- Repository has no security issues (good!)
- Build failed during database creation
- Wrong query suite

**Debug steps**:

```bash
# Check database status
codeql-llm analyze --repo <name> -v

# Check SARIF file directly
cat output/sarif/<lang>/<repo>.sarif | jq '.runs[0].results | length'
```

### Module Not Found: cpp

```
ERROR: could not resolve module cpp
```

**Solution**: Install CodeQL pack dependencies:

```bash
codeql pack install config/queries/tools/cpp
```

### Build Failed

```
CodeQL detected code but could not process it
```

**Solution**: Check the build command in `config/repos.yaml`:

```yaml
- name: myrepo
  url: https://github.com/org/repo.git
  language: c
  build_command: "mkdir build && cd build && cmake .. && make"
```

---

## Next Steps

- Read the full [README.md](README.md) for CLI reference
- Explore [guided questions](config/prompts/guided_questions.yaml)
- Check [security check documentation](docs/)
- Add your own repositories to `config/repos.yaml`

## Getting Help

- Check the [CLI help](codeql-llm --help)
- Review [example scripts](examples/)
- Check [troubleshooting](#troubleshooting) section above
