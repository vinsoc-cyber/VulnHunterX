# Quick Start Guide

Get **SAST (CodeQL / Semgrep / OpenGrep)** + LLM bug verification running in 5 minutes.

## Prerequisites

- **Python 3.12+**
- **CodeQL CLI 2.15+** ([install guide](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/))
- **Semgrep** (optional; [install](https://semgrep.dev/docs/getting-started/))
- **OpenGrep** (optional; [installation](https://github.com/opengrep/opengrep#installation))
- **Git**
- **OpenAI API key**, **Anthropic API key**, or **Ollama** installed locally

## Installation

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git
cd VulnHunterX
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .

# Configure
cp env.example .env
# Edit .env and add: OPENAI_API_KEY=sk-your-key-here

# Verify
vuln-hunter-x check-env
```

## Run Your First Analysis

**Option A: Use example script (recommended)**

```bash
python examples/pipeline_python.py
```

This runs the full pipeline on both `pyyaml` (real-world library) and `dvpwa` (intentionally vulnerable app), demonstrating the contrast between false positives and true positives.

**Option B: Run commands individually**

```bash
vuln-hunter-x prepare --repo pyyaml
vuln-hunter-x analyze --repo pyyaml
vuln-hunter-x verify --repo pyyaml --limit 5
```

## View Results

```bash
cat output/<lang>/<repo>/verification_results/summary_*.json
```

Or generate a readable markdown report:

```bash
vuln-hunter-x report --repo pyyaml --lang python
# Output: output/python/pyyaml/verification_results/report.md
```

You can also generate the report automatically during verification:

```bash
vuln-hunter-x verify --repo pyyaml --limit 5 --report
```

## Example Scripts

Each script runs the full pipeline on **two repos** — one real-world library and one intentionally vulnerable app — to demonstrate the contrast between false positives and true positives.

| Script | Language | Normal package | Vulnerable package |
|--------|----------|---------------|-------------------|
| `examples/pipeline_python.py` | Python | `pyyaml` | `dvpwa` |
| `examples/pipeline_javascript.py` | JavaScript | `minimist` | `nodegoat` |
| `examples/pipeline_c.py` | C | `c-ares` | `dvcp` |
| `examples/pipeline_cpp.py` | C++ | `re2` | `insecure-coding-examples` |
| `examples/pipeline_java.py` | Java | `commons-collections` | `webgoat` |
| `examples/pipeline_php.py` | PHP | `monolog` | `dvwa` |
| `examples/pipeline_go.py` | Go | `gin` | `govwa` |

All scripts support: `--dry-run`, `--skip-clone`, `--api`

C and C++ scripts also support `--fuzz` to run fuzz confirmation stages 5–8.

## Configuration Files

| File | Purpose |
|------|---------|
| `.env` | API keys and paths |
| `config/confirm_findings.yaml` | LLM settings (model, iterations) |
| `config/repos.yaml` | Repositories to analyze |
| `config/prompts/*_questions.yaml` | Per-language guided questions |
| `config/prompts/system_prompt.yaml` | LLM system prompt template |

## Adding Your Own Repository

**Option A: Direct prepare (no config file needed)**

```bash
# Prepare from URL
vuln-hunter-x prepare --url https://github.com/org/my-app.git --lang python

# Use existing local directory
vuln-hunter-x prepare --local-path /path/to/my-app --lang python --name my-app

# For C/C++, provide a build command
vuln-hunter-x prepare --url https://github.com/org/my-lib.git --lang c --build-command "make"

# For Go (no build command needed)
vuln-hunter-x prepare --url https://github.com/org/my-go-app.git --lang go
```

Then analyze and verify — no `repos.yaml` needed, all stages auto-discover from the filesystem:

```bash
vuln-hunter-x analyze --repo my-app                         # CodeQL (default)
vuln-hunter-x analyze --tool semgrep --repo my-app           # Semgrep
vuln-hunter-x analyze --tool all --repo my-app               # CodeQL + Semgrep + OpenGrep
vuln-hunter-x verify --repo my-app --report                  # Verify + generate markdown report
# Context CSVs are extracted automatically during prepare.
# To re-extract: vuln-hunter-x prepare --skip-clone --skip-db --force --repo my-app
```

You can also skip `prepare` and analyze a local directory directly:

```bash
vuln-hunter-x analyze --tool semgrep --local-path /path/to/my-app --lang python
vuln-hunter-x verify --local-path /path/to/my-app --lang python
```

**Option B: Add to repos.yaml**

Edit `config/repos.yaml`:

```yaml
repos:
  - name: my-app
    url: https://github.com/org/my-app.git
    language: python  # or c, cpp, javascript, php, java, go

  - name: my-c-lib
    url: https://github.com/org/my-c-lib.git
    language: c
    build_command: "make"  # Required for C/C++ only
```

Then run:

```bash
vuln-hunter-x prepare --repo my-app
vuln-hunter-x analyze --repo my-app
vuln-hunter-x verify --repo my-app
```

## Common Issues

| Error | Solution |
|-------|----------|
| `CodeQL CLI not found` | Add to PATH or set `CODEQL_PATH` in `.env` |
| `Semgrep CLI not found` | Set `SEMGREP_PATH` in `.env` |
| `OpenAI API key not configured` | Add `OPENAI_API_KEY=sk-...` to `.env` |
| `could not resolve module cpp` | Run `codeql pack install config/queries/tools/cpp` |
| `Database is already finalized` | Normal - analysis proceeds automatically |

## Fuzz-based Confirmation (C/C++)

Optional stages 5-8 confirm C/C++ findings using sanitizer builds and libFuzzer. Full reference: [docs/fuzz_stages.md](docs/fuzz_stages.md).

```bash
vuln-hunter-x build-sanitized --repo libucl
vuln-hunter-x extract-fuzz-context --repo libucl
vuln-hunter-x generate-fuzz-drivers --repo libucl --build --llm-fix
vuln-hunter-x fuzz-run --repo libucl --triage
```

## Next Steps

- See [README.md](README.md) for full CLI reference and API documentation
- Explore [guided questions](config/prompts/) (325+ rules across 7 languages)
- Check [security check docs](docs/) for supported vulnerability types
- [Fuzz stages](docs/fuzz_stages.md) for C/C++ fuzz-based confirmation
