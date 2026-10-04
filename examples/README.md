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
| [`basic_usage.py`](basic_usage.py) | — | Python API usage examples | — |
| [`pipeline_c.py`](pipeline_c.py) | C | c-ares | dvcp |
| [`pipeline_cpp.py`](pipeline_cpp.py) | C++ | re2 | insecure-coding-examples |
| [`pipeline_python.py`](pipeline_python.py) | Python | PyYAML | dvpwa |
| [`pipeline_javascript.py`](pipeline_javascript.py) | JavaScript | minimist | nodegoat |
| [`pipeline_java.py`](pipeline_java.py) | Java | commons-collections | webgoat |
| [`pipeline_php.py`](pipeline_php.py) | PHP | monolog | dvwa |
| [`pipeline_go.py`](pipeline_go.py) | Go | gin | govwa |
| [`pipeline_csharp.py`](pipeline_csharp.py) | C# | newtonsoft-json | WebGoat.NET demo (buildless CodeQL; `--scan` for one-shot) |
| [`pipeline_zlib.py`](pipeline_zlib.py) | C | zlib (single-target, deeper dive) | — |
| [`run_all_pipelines.py`](run_all_pipelines.py) | All | Processes repositories from `config/repos.yaml` | — |

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

1. `prepare` clones the targets under `repos/<lang>/<name>/`, creates CodeQL
   databases, and extracts context CSVs.
2. `analyze` with the configured rule profile.
3. `verify` against the SARIF output with the LLM, producing
   `output/<lang>/<repo>/verification_results/*.json`.
4. Verification generates a report; use `report` to regenerate it from saved
   verdicts. The examples print a per-repository summary.

Pass `--skip-clone` (most scripts) to reuse an existing checkout and
database.

The C, C++, zlib, and batch scripts reject obsolete fuzzing options. Their
supported modes perform static analysis and LLM verification only.
