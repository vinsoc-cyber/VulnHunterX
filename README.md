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
```

Repos and build commands are defined in `config/repos.yaml`. C/C++ entries must include `build_command`; Python and JavaScript do not.

## Later phases

- Phase 3: Run CodeQL static analysis (SARIF output).
- Phase 4: Vulnhalla-style confirmation flow (guided questions + LLM verdicts).
