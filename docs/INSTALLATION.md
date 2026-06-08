# Installation

VulnHunterX is a Python 3.12+ package. The Python install is quick; the **external SAST tools**
(CodeQL especially) are where most first-run problems happen, so this guide covers both and the
failure modes for each.

## 1. Python package

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

[`uv`](https://docs.astral.sh/uv/) is recommended (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
Plain venv works too:

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Tree-sitter grammars (C, C++, Python, JavaScript, Java, PHP, Go) ship with the package — no extra
step. They power the context-extraction fallback when a CodeQL database can't be built.

## 2. External tools

| Tool | Required for | Install |
|---|---|---|
| **CodeQL CLI ≥ 2.15** | Stages 1–3 (DB, analysis, semantic context) | [Getting started](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/) — unzip and add to `PATH`, or set `CODEQL_PATH` in `.env` |
| **Semgrep** | `--tool semgrep` / `both` | `pip install semgrep` |
| **OpenGrep** | `--tool opengrep` / `all` | `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh \| bash` |
| **clang / libFuzzer** | C/C++ fuzz stages 5–8 | system clang ≥ 12 |
| **Atheris / Jazzer / Jazzer.js / php-fuzzer** | Python / Java / JS / PHP fuzzing | see [FUZZING.md](FUZZING.md) |

## 3. Configure an LLM provider

```bash
cp env.example .env
```

Edit `.env` to pick a provider (`LLM_PROVIDER`) and model (`LLM_MODEL`) and add the matching key.
See [LLM_PROVIDERS.md](LLM_PROVIDERS.md) for OpenAI / Anthropic / Ollama details and costs. The
cheapest path to a real run is a local Ollama model (`OLLAMA_API_BASE=http://localhost:11434`),
which costs nothing.

## 4. Verify the toolchain

```bash
vuln-hunter-x check-env
```

This checks the CodeQL CLI, Semgrep/OpenGrep, tree-sitter grammars, and the configured LLM
provider key. Fix anything it flags before running the pipeline.

## 5. First run

```bash
python examples/pipeline_python.py        # clones a real + a vulnerable repo, runs the pipeline
# Useful flags: --dry-run, --skip-clone, --api
```

The example scripts run the full pipeline against a benign real-world library *and* a deliberately
vulnerable app so the false-positive vs. true-positive contrast is visible. One script per
language (`pipeline_python.py`, `pipeline_c.py`, …) — see [examples/](../examples/).

## Per-OS notes

- **Linux / WSL2** — primary target; everything works as documented.
- **macOS** — fine for stages 1–4. For C/C++ fuzzing, install LLVM/clang via Homebrew
  (`brew install llvm`) and put it ahead of the Apple toolchain on `PATH`.
- **Windows** — use WSL2. CodeQL and the fuzzers expect a POSIX toolchain.

## Common setup failures

| Symptom | Cause / fix |
|---|---|
| `CodeQL CLI not found` | Not on `PATH` — add it or set `CODEQL_PATH` in `.env`. |
| `could not resolve module cpp` | Context query pack not installed: `codeql pack install config/queries/tools/cpp`. |
| `Database is already finalized` | Harmless — analysis proceeds automatically. |
| `Semgrep CLI not found` | `pip install semgrep` or set `SEMGREP_PATH`. |
| Semgrep/OpenGrep "0 results" | Registry `p/...` packs need network access; offline, use `--profile full` for in-repo rules. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md). |
| `OpenAI API key not configured` | Add `OPENAI_API_KEY=sk-...` to `.env`, or switch `LLM_PROVIDER`. |

More detail per stage in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
