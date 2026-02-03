# CodeQLxLLM

Demo: LLM-enhanced bug verification for CodeQL findings (OpenAI and Ollama).  
See [the plan](.cursor/plans/codeql_llm_bug_verification_demo_692ae989.plan.md) for full phases.

## Phase 1: Environment check

Verify CodeQL CLI and LLM providers (OpenAI, Ollama via LiteLLM).

### Prerequisites

- Python 3.12 or 3.13
- [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases) on `PATH` (or set `CODEQL_PATH`)
- Optional: `OPENAI_API_KEY` for OpenAI; running Ollama (local or set `OLLAMA_API_BASE` for a remote server)

### Setup

```bash
# Create venv and install deps
uv venv --python python3.12 .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
uv pip install -e .
```

Copy `.env.example` to `.env` and set any of: `CODEQL_PATH`, `OPENAI_API_KEY`, `OPENAI_MODEL`, `OLLAMA_MODEL`, `OLLAMA_API_BASE` (for Ollama on another server).

### Run Phase 1 check

```bash
python scripts/check_env.py
```

- **CodeQL**: Must be available for later phases (clone + DB + analysis).
- **OpenAI** / **Ollama**: Optional for Phase 1; required for LLM verification in Phase 4.

## Phase 2: Clone repos and create CodeQL databases

Clone repositories from `config/repos.yaml` into `repos/<lang>/<name>/` and create CodeQL databases in `databases/<lang>/<name>/`.

### Prerequisites

- Phase 1 done (venv, CodeQL CLI on `PATH` or `CODEQL_PATH`)
- Git access to GitHub (for clone); no auth needed for public repos in normal setups

### Run Phase 2

```bash
# Dry-run (print actions only)
python scripts/clone_and_db.py --dry-run

# Clone and create DBs for all repos in config
python scripts/clone_and_db.py

# Only one language
python scripts/clone_and_db.py --lang javascript

# Only one repo
python scripts/clone_and_db.py --repo minimist

# Clone only (skip CodeQL DB create)
python scripts/clone_and_db.py --skip-db

# Skip clone (repos already present)
python scripts/clone_and_db.py --skip-clone

# On CodeQL DB failure, send full error + repo info to LLM for concrete fix commands and suggested build_command
python scripts/clone_and_db.py --repo re2 --ask-llm
```

Repos and build commands are defined in `config/repos.yaml`. C/C++ entries must include `build_command`; Python and JavaScript do not. Build commands are written to `repo_root/.codeql_build.sh` and that script path is passed to CodeQL (avoids space-splitting of `cmake . && make`). On failure, use `--ask-llm` to send the full error and repo URL to an LLM; the LLM returns concrete shell commands to run and an optional `Suggested build_command:` for `config/repos.yaml`. Errors are saved under `output/db_errors/`.

## Phase 3: Run CodeQL static analysis

Run CodeQL security-extended suites on databases from Phase 2 and write SARIF (and optional findings JSON).

### Prerequisites

- Phase 2 done: CodeQL databases under `databases/<lang>/<name>/`
- CodeQL CLI on `PATH` (or `CODEQL_PATH`); query packs available (run `codeql pack download` if needed)

### Run Phase 3

```bash
# Dry-run (print actions only)
python scripts/run_codeql_analysis.py --dry-run

# Run analysis on all discovered DBs; SARIF -> output/sarif/<lang>/<name>.sarif
python scripts/run_codeql_analysis.py

# Also write findings JSON for Phase 4 (output/findings/<lang>/<name>.json)
python scripts/run_codeql_analysis.py --json

# Only one language
python scripts/run_codeql_analysis.py --lang javascript

# Only one repo
python scripts/run_codeql_analysis.py --repo minimist
```

Suites used: `codeql/cpp-queries:codeql-suites/cpp-security-extended.qls` (C/C++), `codeql/python-queries:...`, `codeql/javascript-queries:...` for Python/JavaScript.

### Security Checks Documentation

For detailed information on security checks, vulnerability types, and detection methods:

- **[Overview](docs/codeql_security_checks.md)** - How CodeQL works, taint tracking, SARIF format
- **[C/C++ Security](docs/codeql_cpp_security.md)** - Buffer overflow, use-after-free, format strings, etc.
- **[Python Security](docs/codeql_python_security.md)** - SQL injection, deserialization, XSS, SSRF, etc.
- **[JavaScript Security](docs/codeql_javascript_security.md)** - Prototype pollution, XSS, command injection, etc.

## Later phases

- Phase 4: Vulnhalla-style confirmation flow (guided questions + LLM verdicts).
