# Quick Start Guide

Get CodeQL + LLM bug verification running in 5 minutes.

## Prerequisites

- **Python 3.12+**
- **CodeQL CLI 2.15+** ([install guide](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/))
- **Git**
- **OpenAI API key** or **Ollama** installed locally

## Installation

```bash
# Clone and install
git clone https://github.com/your-org/CodeQLxLLM.git
cd CodeQLxLLM
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .

# Configure
cp env.example .env
# Edit .env and add: OPENAI_API_KEY=sk-your-key-here

# Verify
codeql-llm check-env
```

## Run Your First Analysis

**Option A: Use example script (recommended)**

```bash
python examples/pipeline_python.py
```

This clones `pyyaml`, runs CodeQL analysis, and verifies findings with LLM.

**Option B: Run commands individually**

```bash
codeql-llm clone --repo pyyaml
codeql-llm analyze --repo pyyaml
codeql-llm verify --repo pyyaml --limit 5
```

## View Results

```bash
cat output/results/summary_*.json
```

Output shows verdicts (True Positive, False Positive, Needs More Data) with confidence and reasoning.

## Example Scripts

| Script | Language | Notes |
|--------|----------|-------|
| `examples/pipeline_python.py` | Python | Fastest (no compilation) |
| `examples/pipeline_javascript.py` | JavaScript | Known vulnerabilities |
| `examples/pipeline_c.py` | C | Requires build tools |
| `examples/pipeline_cpp.py` | C++ | Requires CMake |

All scripts support: `--dry-run`, `--skip-clone`, `--simple`, `--compare`, `--api`

## Configuration Files

| File | Purpose |
|------|---------|
| `.env` | API keys and paths |
| `config/confirm_findings.yaml` | LLM settings (model, mode, iterations) |
| `config/repos.yaml` | Repositories to analyze |
| `config/prompts/guided_questions.yaml` | Rule-specific questions |

## Adding Your Own Repository

Edit `config/repos.yaml`:

```yaml
repos:
  - name: my-app
    url: https://github.com/org/my-app.git
    language: python  # or c, cpp, javascript
    # build_command: "make"  # Required for C/C++ only
```

Then run:

```bash
codeql-llm clone --repo my-app
codeql-llm analyze --repo my-app
codeql-llm verify --repo my-app
```

## Common Issues

| Error | Solution |
|-------|----------|
| `CodeQL CLI not found` | Add to PATH or set `CODEQL_PATH` in `.env` |
| `OpenAI API key not configured` | Add `OPENAI_API_KEY=sk-...` to `.env` |
| `could not resolve module cpp` | Run `codeql pack install config/queries/tools/cpp` |
| `Database is already finalized` | Normal - analysis proceeds automatically |

## Next Steps

- See [README.md](README.md) for full CLI reference and API documentation
- Explore [guided questions](config/prompts/guided_questions.yaml)
- Check [security check docs](docs/) for supported vulnerability types
