# Examples

End-to-end runnable scripts that drive the full VulnHunterX pipeline
against real targets. Each per-language script clones one real-world
library plus one intentionally-vulnerable repo so the TP-vs-FP contrast
is visible in the report.

## Quick start

```bash
# from the repo root, with .env configured (OPENAI/ANTHROPIC/OLLAMA)
python examples/pipeline_python.py
```

Each script accepts `--dry-run` to print the commands without executing
the LLM-backed verify stage (useful for smoke-testing the wiring).

## Scripts

| Script | Language | Real-world target | Vulnerable target |
| --- | --- | --- | --- |
| [`basic_usage.py`](basic_usage.py) | — | Minimal Python-API smoke test (no clone, no LLM call) — verifies `import vuln_hunter_x` works. |
| [`pipeline_c.py`](pipeline_c.py) | C | libxml2 | dvpwa-c (deliberately vulnerable C demo) |
| [`pipeline_cpp.py`](pipeline_cpp.py) | C++ | leveldb | dvpwa-cpp |
| [`pipeline_python.py`](pipeline_python.py) | Python | PyYAML | dvpwa |
| [`pipeline_javascript.py`](pipeline_javascript.py) | JavaScript | express | NodeGoat-style demo |
| [`pipeline_java.py`](pipeline_java.py) | Java | jackson-databind | WebGoat-style demo |
| [`pipeline_php.py`](pipeline_php.py) | PHP | symfony | DVWA-style demo |
| [`pipeline_go.py`](pipeline_go.py) | Go | gin | gosec-baseline demo |
| [`pipeline_csharp.py`](pipeline_csharp.py) | C# | newtonsoft-json | WebGoat.NET demo (buildless CodeQL; `--scan` for one-shot) |
| [`pipeline_zlib.py`](pipeline_zlib.py) | C | zlib (single-target, deeper dive) | — |
| [`run_all_pipelines.py`](run_all_pipelines.py) | All | Iterates every per-language pipeline above. Heavy — use a local Ollama model. |

Per-script config (target repo names, `MAX_FINDINGS`, `MAX_ITERATIONS`)
lives at the top of each file. Override targets by editing the `REPOS`
list in place.

## Requirements

- A working VulnHunterX install (`uv pip install -e ".[dev]"`).
- CodeQL CLI 2.15+ on `$PATH` (or `CODEQL_PATH` in `.env`).
- `.env` configured with an LLM provider (see top-level
  [README.md](../README.md#install)).
- Disk: ~2 GB per language run (CodeQL DBs + repo clones).

## How a pipeline runs

1. Clone the real + vulnerable repos under `repos/<lang>/<name>/` and
   create CodeQL databases.
2. `analyze` with the configured rule profile.
3. `extract-context` to populate `output/<lang>/<repo>/context/*.csv`.
4. `verify` against the SARIF output with the LLM, producing
   `output/<lang>/<repo>/verification_results/*.json`.
5. Print a per-repo summary table.

Pass `--skip-clone` (most scripts) to reuse an existing checkout and
database.
