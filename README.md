# VulnHunterX

**SAST (CodeQL, Semgrep, OpenGrep) + fuzzing + LLM vulnerability hunting and verification**

A Python framework that pairs static analysis with multi-turn LLM verification to suppress false positives in SAST findings, implementing the *Vulnhalla* methodology of guided-question, evidence-anchored triage.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![SAST](https://img.shields.io/badge/SAST-CodeQL%20%7C%20Semgrep%20%7C%20OpenGrep-orange.svg)

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Pipeline Stages](#pipeline-stages)
- [CLI Reference](#cli-reference)
- [Python API](#python-api)
- [Rules & Coverage](#rules--coverage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Development](#development)
- [Benchmark](#benchmark)
- [References](#references)

---

## Overview

SAST engines deliberately over-approximate — they flag every program point that *might* be vulnerable. The dominant cost of running them in production is not analysis time but human triage. VulnHunterX automates triage by feeding each SARIF finding to an LLM that must answer a rule-specific checklist of evidence-anchored questions, request additional code context when needed (multi-turn), and emit a structured verdict with a confidence score.

```
Source  ──>  Static Analysis  ──>  SARIF Findings  ──>  LLM Verification  ──>  Verdicts
(prepare)    (CodeQL/Semgrep/      (rule, file,          (guided questions,      (TP/FP/NMD +
              OpenGrep)             line, severity)       multi-turn context)     confidence)
```

The **Vulnhalla** methodology forces the LLM to:

- answer rule-specific guided questions *before* committing to a verdict,
- request callers, structs, globals, free-sites, etc. as needed via a fixed context vocabulary,
- reason across multiple turns rather than pattern-match a single snippet.

### Key features

| Feature | Description |
|---|---|
| **Languages** | 7 — C, C++, Python, JavaScript, PHP, Java, Go |
| **SAST engines** | CodeQL, Semgrep, OpenGrep (`--tool codeql|semgrep|opengrep|both|all`) |
| **Rule profiles** | 5 — `standard` → `extended` → `maximum` → `extended-registry` → `full` (see [config/RULES.md](config/RULES.md)) |
| **Guided questions** | 316 rule-specific templates across 6 per-language banks plus a fallback |
| **LLM providers** | OpenAI, Anthropic, Ollama (via [LiteLLM](https://github.com/BerriAI/litellm)) |
| **Multi-turn verification** | Dynamic context expansion (callers, structs, globals, macros, free-sites) |
| **Inputs** | Git URL, local directory, or batch list (`repos.yaml`) |
| **Reports** | Markdown, EN/VI, executive summary + per-finding detail |
| **Fuzz confirmation** | libFuzzer / Atheris / Jazzer / Jazzer.js / php-fuzzer harness generation + crash triage |
| **Benchmarking** | Precision/recall across 6 ground-truth datasets (see [benchmarks/README.md](benchmarks/README.md)) |

---

## Quick Start

### Prerequisites

- Python 3.12+
- [CodeQL CLI 2.15+](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/)
- [Semgrep](https://semgrep.dev/docs/getting-started/) and/or [OpenGrep](https://github.com/opengrep/opengrep#installation) — optional
- An LLM provider: OpenAI, Anthropic, or local Ollama

### Install

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .

cp env.example .env       # add OPENAI_API_KEY / ANTHROPIC_API_KEY / OLLAMA_API_BASE
vuln-hunter-x check-env   # verify toolchain
```

### First run

The fastest path is one of the per-language example scripts under [examples/](examples/), which clone a real-world target, a vulnerable target, and run the full pipeline against both so the FP-vs-TP contrast is visible:

```bash
python examples/pipeline_python.py
# Common flags: --dry-run, --skip-clone, --api ; C/C++ scripts also support --fuzz
```

| Script | Language | Real-world | Vulnerable |
|---|---|---|---|
| `pipeline_python.py` | Python | pyyaml | dvpwa |
| `pipeline_javascript.py` | JavaScript | minimist | nodegoat |
| `pipeline_c.py` | C | c-ares | dvcp |
| `pipeline_cpp.py` | C++ | re2 | insecure-coding-examples |
| `pipeline_java.py` | Java | commons-collections | webgoat |
| `pipeline_php.py` | PHP | monolog | dvwa |
| `pipeline_go.py` | Go | gin | govwa |

### Or run stages directly

```bash
vuln-hunter-x prepare --repo pyyaml
vuln-hunter-x analyze --repo pyyaml --profile extended
vuln-hunter-x verify  --repo pyyaml --limit 5
vuln-hunter-x report  --repo pyyaml --lang python
```

### Add your own repository

```bash
# Single-shot from URL
vuln-hunter-x prepare --url https://github.com/org/app.git --lang python

# Existing checkout
vuln-hunter-x prepare --local-path /path/to/app --lang python --name app

# Compiled languages need a build command
vuln-hunter-x prepare --url https://github.com/org/lib.git --lang c --build-command "make"
```

Or list it under `repos:` in [config/repos.yaml](config/repos.yaml) and run `vuln-hunter-x prepare --repo <name>`.

### Troubleshooting

| Symptom | Fix |
|---|---|
| `CodeQL CLI not found` | Add to `PATH` or set `CODEQL_PATH` in `.env` |
| `Semgrep CLI not found` | Set `SEMGREP_PATH` in `.env` |
| `OpenAI API key not configured` | Add `OPENAI_API_KEY=sk-...` to `.env` |
| `could not resolve module cpp` | `codeql pack install config/queries/tools/cpp` |
| `Database is already finalized` | Normal — analysis proceeds automatically |

---

## Pipeline Stages

| # | Command | Input | Output |
|---|---|---|---|
| 1 | `prepare` (alias `clone`) | URL / local path / `repos.yaml` | Source + CodeQL DB + context CSVs |
| 2 | `analyze` | CodeQL DB and/or source tree | SARIF findings |
| 3 | `verify` | SARIF + context CSVs | JSON verdicts + reasoning |
| 4 | `report` | Verification results | Markdown report (EN/VI) |
| 5 | `build-sanitized` | Verified C/C++ findings | ASan/UBSan build manifest |
| 6 | `extract-fuzz-context` | C/C++ source | Function signatures for harness generation |
| 7 | `generate-fuzz-drivers` | Fuzz context + sanitized build | libFuzzer / Atheris / Jazzer harnesses |
| 8 | `fuzz-run` | Compiled harnesses | Crash files + triage results |

| Goal | Required stages | Optional |
|---|---|---|
| Static analysis only | 1, 2 | — |
| LLM verification | 1, 2, 3 | 4 (`report`) |
| Fuzz confirmation | 1, 2, 3, 5, 6, 7, 8 | 4 (`report`) |

Stages 2–3 accept `--local-path` to operate directly on an arbitrary directory.

---

## CLI Reference

### `check-env`

```bash
vuln-hunter-x check-env
```

Verifies CodeQL CLI, Semgrep/OpenGrep, and LLM provider keys.

### `prepare` *(alias: `clone`)*

Clone a repository, create a CodeQL database, and extract context CSVs (functions, callers, structs, globals, macros, classes).

```bash
vuln-hunter-x prepare                                                 # batch from repos.yaml
vuln-hunter-x prepare --url https://github.com/org/repo.git --lang go
vuln-hunter-x prepare --local-path /path/to/repo --lang python
vuln-hunter-x prepare --skip-clone --skip-db --force --repo libucl    # re-extract context only
```

| Option | Description | Default |
|---|---|---|
| `--config PATH` | Path to `repos.yaml` | — |
| `--url URL` | Git URL to clone | — |
| `--local-path PATH` | Existing local directory | — |
| `--name NAME` | Repository name (auto-derived if omitted) | — |
| `--lang LANG` | Language — required with `--url` or `--local-path` | — |
| `--build-command CMD` | Build command for compiled languages | — |
| `--repo NAME` | Filter to one repository (config mode) | All |
| `--skip-clone` / `--skip-db` / `--skip-context` | Skip stages | false |
| `--backend {auto,codeql,treesitter}` | Context extraction backend | `auto` |
| `--ask-llm` | Ask the LLM for help if the build fails | false |
| `-f, --force` | Force re-extraction of context CSVs | false |
| `--dry-run` | Preview actions | false |

### `analyze`

Run CodeQL, Semgrep, and/or OpenGrep against a prepared repo or a local path.

```bash
vuln-hunter-x analyze --repo libucl
vuln-hunter-x analyze --tool all --repo c-ares --profile full
vuln-hunter-x analyze --tool semgrep --local-path /path/to/project --lang python --profile extended
```

| Option | Description | Default |
|---|---|---|
| `--tool {codeql,semgrep,opengrep,both,all}` | Analyzer(s) | `codeql` |
| `--profile {standard,extended,maximum,extended-registry,full}` | Rule profile (see [config/RULES.md](config/RULES.md)) | `standard` |
| `--category CAT` | Filter by security category (repeatable) | All |
| `--local-path PATH` | Analyze a local directory | — |
| `--name NAME` | Repository name | auto-derived |
| `--semgrep-config CFG` / `--opengrep-config CFG` | Override rule pack(s) | from profile |
| `--codeql-suite SUITE` | Override CodeQL suite | from profile |
| `--repo NAME` / `--lang LANG` | Filters | All |
| `-j, --jobs N` | Parallel CodeQL analyses | 2 |
| `--json` | Also output findings JSON | false |
| `-f, --force` | Re-run even if SARIF exists | false |
| `--dry-run` / `-v` | Preview / verbose | false |

### `verify`

Verify SARIF findings using multi-turn LLM reasoning.

```bash
vuln-hunter-x verify --repo libucl
vuln-hunter-x verify --repo c-ares --lang c --category memory-safety
vuln-hunter-x verify --provider ollama --model ollama/llama3.2 --repo libucl
vuln-hunter-x verify --local-path /path/to/project --lang python --limit 20
```

| Option | Description | Default |
|---|---|---|
| `--config PATH` | Configuration file | `config/confirm_findings.yaml` |
| `--local-path PATH` | Verify findings for a local directory | — |
| `--name NAME` | Repository name | auto-derived |
| `--repo NAME` / `--lang LANG` | Filters | All |
| `--sarif PATH` | Process a specific SARIF file | — |
| `--provider {openai,anthropic,ollama}` | LLM provider | from config |
| `--model NAME` | Model name | from config |
| `--temperature F` / `--max-tokens N` | LLM tuning | from config |
| `--max-iterations N` | Max conversation rounds per finding | 3 |
| `--limit N` | Maximum findings to process | Unlimited |
| `--category CAT` | Filter by category (repeatable, same vocabulary as `analyze`) | All |
| `--include-tests` | Include findings under `test/`, `tests/` | false |
| `-v` / `-q` | Verbose / quiet | normal |
| `--log-file PATH` | Persist LLM conversations | — |
| `--dry-run` | Preview findings | false |

### `report`

Generate a markdown report from verification results. `verify` already writes `report.md` and `report_vi.md`; use this to regenerate or change the output path.

```bash
vuln-hunter-x report --repo c-ares --lang c
vuln-hunter-x report --results-dir output/c/c-ares/verification_results
vuln-hunter-x report --repo libucl -o my-report.md --lang-report en
```

| Option | Description | Default |
|---|---|---|
| `--results-dir PATH` | Path to a `verification_results/` directory | auto-discover |
| `--repo NAME` / `--lang LANG` | Auto-discover by repo and language | — |
| `-o, --output PATH` | Output path | `report.md` in results dir |
| `--lang-report {en,vi,all}` | Report language(s) | `all` |

Report sections: executive summary · findings overview (before/after verdicting) · severity breakdown · CWE distribution · per-finding detail (verdict, confidence, reasoning, dataflow).

### Fuzz stages (C/C++ only)

```bash
vuln-hunter-x build-sanitized       --repo libucl
vuln-hunter-x extract-fuzz-context  --repo libucl
vuln-hunter-x generate-fuzz-drivers --repo libucl --build --llm-fix
vuln-hunter-x fuzz-run              --repo libucl --triage
```

Run any subcommand with `--help` for full options.

### `info`

```bash
vuln-hunter-x info
```

Prints the resolved configuration — provider, model, paths.

---

## Python API

```python
from pathlib import Path
from vuln_hunter_x import VerificationEngine
from vuln_hunter_x.reporting.markdown import MarkdownReportGenerator

engine = VerificationEngine.from_config("config/confirm_findings.yaml")
result = engine.verify_sarif("output/c/libucl/libucl.sarif", lang="c", repo_name="libucl")

for verdict in result.verdicts:
    print(f"{verdict.finding.rule_id}: {verdict.verdict} ({verdict.confidence})")

engine.save_results(result)
MarkdownReportGenerator().generate(
    result, Path("output/c/libucl/verification_results/report.md")
)
```

---

## Rules & Coverage

[config/RULES.md](config/RULES.md) is the authoritative inventory — every profile, every custom CodeQL query, every custom Semgrep rule, with CWE tags and severities. Quick summary:

| Metric | Count |
|---|---|
| Rule profiles | 5 (`standard` → `full`) |
| Security categories | 12 |
| CWE entries in routing map | 103 |
| Custom CodeQL queries | 6 (5 C/C++, 1 Go) |
| Custom Semgrep rules | 14 (Python 4, JS/TS 3, Go 3, PHP 4) |
| Built-in CodeQL suites | `security-extended` (~200), `security-and-quality` (~400) |
| Built-in Semgrep universal packs | 8 |
| Built-in Semgrep per-language packs | 10 (django, flask, nodejs, gosec, …) |
| Guided-question templates | 316 across 6 per-language banks + 1 fallback |

Coverage growth from `--profile standard` to `--profile full` is roughly **5×–10×** more rules per scan. Per-language registry packs (`p/django`, `p/gosec`, …) are only applied to matching repos so cross-language scans aren't polluted.

To add a custom rule:

- **CodeQL** — drop `<name>.ql` into `config/codeql-custom/<lang>/src/` with `@id <lang>/<name>` matching a guided-question key.
- **Semgrep** — append a rule to `config/semgrep-custom/<lang>.yaml` with `metadata.cwe: ["CWE-NNN"]` so CWE-based routing works.

Both are activated by `--profile full`. Run `python scripts/audit_rule_coverage.py --fail-on-gaps` to verify the wiring.

---

## Configuration

Priority: **CLI args > environment variables > config file > defaults**.

### Environment variables (`.env`)

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `OLLAMA_API_BASE` | Ollama server URL |
| `LLM_PROVIDER` / `LLM_MODEL` | Override default provider / model |
| `CODEQL_PATH` / `SEMGREP_PATH` / `OPENGREP_PATH` | Tool paths if not on `PATH` |

### LLM / verification settings (`config/confirm_findings.yaml`)

```yaml
provider: openai          # openai | anthropic | ollama
model: gpt-4o
temperature: 0.2
max_tokens: 1500
max_iterations: 3         # conversation rounds per finding
```

### Repository list (`config/repos.yaml`)

```yaml
repos:
  - name: pyyaml
    url: https://github.com/yaml/pyyaml.git
    language: python

  - name: libucl
    url: https://github.com/vstakhov/libucl.git
    language: c
    build_command: "mkdir -p build && cd build && cmake .. && make"
```

| Field | Description |
|---|---|
| `name` | Short identifier used in output paths |
| `url` | Git clone URL |
| `language` | `c` · `cpp` · `python` · `javascript` · `php` · `java` · `go` |
| `build_command` | Required for C/C++; omit for interpreted languages |

### Guided questions (`config/prompts/`)

Rule-specific question banks that force the LLM to reason step-by-step.

| File | Language | Rule sets |
|---|---|---|
| `cpp_questions.yaml` | C/C++ | 59 |
| `python_questions.yaml` | Python | 56 |
| `javascript_questions.yaml` | JavaScript / TypeScript | 51 |
| `go_questions.yaml` | Go | 50 |
| `java_questions.yaml` | Java | 50 |
| `php_questions.yaml` | PHP | 50 |
| `default_questions.yaml` | Fallback | 1 |

The verifier matches each SARIF `ruleId` in three tiers — exact match → prefix/normalized → CWE map — falling back to `default_questions.yaml` only when none hits. See [config/RULES.md § 7](config/RULES.md#7-guided-question-routing).

---

## Project Structure

```
VulnHunterX/
├── src/vuln_hunter_x/
│   ├── cli/           # CLI commands
│   ├── codeql/        # Database creation, analysis, context extraction
│   ├── context/       # Heuristic + tree-sitter context extraction
│   ├── core/          # Types, config, constants
│   ├── dyntest/       # Language backends for fuzz stages 5–8
│   ├── fuzz/          # C/C++ fuzz shims
│   ├── llm/           # LLM client (LiteLLM) and prompt construction
│   ├── opengrep/      # OpenGrep integration
│   ├── questions/     # Guided-question loader
│   ├── reporting/     # Markdown report generation
│   ├── sarif/         # SARIF parsing
│   ├── semgrep/       # Semgrep integration
│   └── verification/  # Multi-turn verification engine
├── config/
│   ├── RULES.md                # Authoritative rule inventory
│   ├── rule_categories.yaml    # Profiles, categories, CWE map
│   ├── codeql-custom/          # Custom CodeQL queries (full profile)
│   ├── semgrep-custom/         # Custom Semgrep rules (full profile)
│   ├── prompts/                # Guided questions + system prompt
│   ├── queries/                # CodeQL context queries (per language)
│   ├── confirm_findings.yaml   # LLM and verification settings
│   └── repos.yaml              # Repository definitions
├── benchmarks/        # Evaluation framework — see benchmarks/README.md
├── examples/          # Per-language pipeline scripts
├── scripts/           # audit_rule_coverage.py, etc.
├── tests/
└── output/
    └── <lang>/<repo>/
        ├── database/              # CodeQL database
        ├── *.sarif                # SARIF results
        ├── context/               # Extracted CSVs
        ├── verification_results/  # Verdict JSON + report.md
        ├── sanitized_build/       # (C/C++) sanitizer build
        ├── fuzz_targets/          # (C/C++) harnesses
        └── fuzz_results/          # (C/C++) crashes
```

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/
ruff check src/
ruff format src/
mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

---

## Benchmark

VulnHunterX ships a standalone benchmark framework comparing the full pipeline against `raw-sast` and ablation baselines on six ground-truth datasets (SecLLMHolmes, Juliet C/C++, DiverseVul, OWASP BenchmarkJava, OWASP BenchmarkPython, RealVuln).

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all \
    --model gpt-4o-mini --limit 50
```

Full documentation — datasets, per-dataset playbooks, metrics, resume semantics — lives in [benchmarks/README.md](benchmarks/README.md). The literature review and design-decision rationale are in [benchmarks/RESEARCH.md](benchmarks/RESEARCH.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [Vulnhalla — CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack) — original methodology
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
