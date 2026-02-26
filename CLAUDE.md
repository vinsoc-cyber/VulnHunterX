# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
uv venv --python python3.12 .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Tests
pytest tests/
pytest tests/test_specific.py::test_name  # single test

# Lint / format
ruff check src/
ruff format src/

# Type check
mypy src/

# CLI entry point (after install)
vuln-hunter-x <command> [options]
```

## Architecture

VulnHunterX is an 8-stage pipeline that combines SAST tools (CodeQL, Semgrep) with LLM-based verification to reduce false positives in security findings, implementing the **Vulnhalla methodology**.

### Pipeline Stages

**Stages 1–4: Core analysis (all languages: C, C++, Python, JavaScript)**
1. `clone` — Clone repos and create CodeQL databases
2. `analyze` — Run CodeQL / Semgrep / both (produces `*.sarif` files)
3. `extract-context` — Pre-extract function/caller/struct/global/macro context as CSVs
4. `verify` — Multi-turn LLM verification with guided questions; discovers all `*.sarif` in output dir

**Stages 5–8: Optional fuzz confirmation (C/C++ only)**
5. `build-sanitized` — Build with ASan/UBSan
6. `extract-fuzz-context` — Extract function signatures and includes
7. `generate-fuzz-drivers` — Generate libFuzzer harnesses (LLM-assisted compilation fixes)
8. `fuzz-run` — Execute fuzzers and collect crashes

### Source Layout

```
src/vuln_hunter_x/
├── cli/           # CLI commands (main.py, commands.py)
├── codeql/        # Database creation, analysis runner, context queries
├── semgrep/       # SemgrepAnalyzer (produces separate SARIF)
├── context/       # ContextExtractor (heuristic) + ContextProvider (CSV-based)
├── core/          # Config (3-tier priority) and types
├── llm/           # LLMClient (LiteLLM-backed), PromptBuilder
├── questions/     # Loads guided questions YAML; fallback to generic questions
├── sarif/         # SARIF parser; discovers all *.sarif in repo output dir
├── verification/  # VerificationEngine orchestrating multi-turn LLM flow
└── fuzz/          # Stages 5–8 modules
```

### Key Data Flow

```
SARIF files
  └─► SarifParser → [Finding]
        └─► VerificationEngine
              ├── QuestionsLoader  (rule-specific guided questions)
              ├── ContextProvider  (CSV look-ups from pre-extracted context)
              └── LLMClient (LiteLLM → OpenAI or Ollama)
                    └─► Verdict (TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_MORE_DATA)
```

Multi-turn: the LLM can request more context; `VerificationEngine` fetches additional CSV rows and continues the conversation up to `max_iterations`.

### Configuration (3-tier priority: CLI args > env vars > config file > defaults)

| File | Purpose |
|---|---|
| `.env` | Secrets: `OPENAI_API_KEY`, `LLM_PROVIDER`, `LLM_MODEL`, `CODEQL_PATH`, `SEMGREP_PATH`, `OLLAMA_API_BASE` |
| `config/confirm_findings.yaml` | App settings: model, temperature, max_iterations, verbosity, paths, filters |
| `config/repos.yaml` | Repository list with names, URLs, languages, optional build commands |
| `config/prompts/guided_questions.yaml` | Per-rule guided questions (4–6 questions each, e.g. `cpp/use-after-free`) |
| `config/queries/tools/<lang>/` | CodeQL `.ql` extraction queries (functions, callers, structs, globals, macros) |

### Python API

```python
from vuln_hunter_x import VerificationEngine

engine = VerificationEngine.from_config("config/confirm_findings.yaml")
result = engine.verify_sarif("output/c/repo/repo.sarif", lang="c", repo_name="repo")
```

### Output Structure

```
output/<lang>/<repo_name>/
├── database/             # CodeQL database
├── *.sarif               # CodeQL and/or Semgrep SARIF results
├── context/              # Pre-extracted CSV context files
└── verification_results/ # Verdict JSON files per finding
```

### External Tool Dependencies

- **CodeQL CLI** ≥ 2.15 (required for stages 1, 2, 3)
- **Semgrep** (optional; required only when `--tool semgrep` or `--tool both`)
- **libFuzzer / clang** (optional; required for fuzz stages 5–8)

Use `vuln-hunter-x check-env` to verify all dependencies.
