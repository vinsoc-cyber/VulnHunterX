# VulnHunterX

**SAST (CodeQL, Semgrep, OpenGrep) + fuzzing + LLM vulnerability hunting and verification**

A Python framework that combines static analysis with LLM verification to reduce false positives in security findings, implementing the Vulnhalla methodology for intelligent, multi-turn bug confirmation.

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
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Benchmark](#benchmark)
- [References](#references)

---

## Overview

Static analysis tools (CodeQL, Semgrep, OpenGrep) produce many findings, but a significant portion are false positives. VulnHunterX automates triage by using LLMs to analyze code context, answer rule-specific guided questions, request additional context when needed (multi-turn), and produce verdicts with confidence levels and reasoning.

### Key Features

| Feature | Description |
|---|---|
| **Multi-language** | C, C++, Python, JavaScript, PHP, Java, Go |
| **Multi SAST** | CodeQL, Semgrep, OpenGrep (`--tool codeql|semgrep|opengrep|both|all`) |
| **LLM verification** | Multi-turn with dynamic context expansion (callers, structs, globals) |
| **Guided questions** | 325+ rule-specific templates across 7 languages |
| **Multiple LLM providers** | OpenAI (GPT-4), Anthropic (Claude), Ollama (local) |
| **Flexible input** | Clone from URL, use local directory, or batch via `repos.yaml` |
| **Markdown reports** | Executive summary, severity/CWE breakdown, per-finding detail |
| **Fuzz confirmation** | libFuzzer harness generation + crash triage (C/C++ only) |
| **Benchmarking** | Precision/recall across 4 ground-truth datasets |

### How It Works

```
Source  ──>  Static Analysis  ──>  SARIF Findings  ──>  LLM Verification  ──>  Verdicts
(prepare)    (CodeQL/Semgrep/      (rule, file,          (guided questions,      (TP/FP/NMD +
              OpenGrep)             line, severity)       multi-turn context)     confidence)
```

The **Vulnhalla methodology** improves accuracy by forcing the LLM to:
- Answer rule-specific questions before giving a verdict
- Request callers, structs, globals, or other context as needed
- Reason across multiple turns rather than pattern-matching

---

## Quick Start

```bash
# Install
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .

# Configure
cp env.example .env   # add OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_API_BASE

# Verify setup
vuln-hunter-x check-env

# Run the full pipeline
vuln-hunter-x prepare --repo pyyaml
vuln-hunter-x analyze --repo pyyaml
vuln-hunter-x verify --repo pyyaml --limit 5 --report
```

For detailed setup, see [QUICKSTART.md](QUICKSTART.md).

---

## Pipeline Stages

| Stage | Command | Input | Output |
|---|---|---|---|
| 1 | `prepare` | URL / local path / repos.yaml | Source code + CodeQL database |
| 2 | `analyze` | CodeQL DB and/or source tree | SARIF findings |
| 3 | `extract-context` | CodeQL DB or source tree | CSV context files |
| 4 | `verify` | SARIF + CSVs | JSON verdicts + reasoning |
| — | `report` | Verification results | Markdown report |
| 5–8 | `build-sanitized` → `fuzz-run` | Verified C/C++ findings | Fuzz harnesses + crash results |

Stages 2–4 accept `--local-path` to operate directly on an arbitrary directory. See [docs/fuzz_stages.md](docs/fuzz_stages.md) for stages 5–8.

| Goal | Required stages | Optional |
|---|---|---|
| Static analysis only | 1, 2 | — |
| LLM verification | 1, 2, 4 | 3 |
| Fuzz confirmation (C/C++) | 1, 2, 4, 5, 6, 7 | 3, 8 |

---

## CLI Reference

### check-env

```bash
vuln-hunter-x check-env
```

Checks CodeQL CLI, Semgrep/OpenGrep, and LLM provider keys.

---

### prepare *(alias: clone)*

Clone a repository and create a CodeQL database. Accepts a config file, a direct URL, or a local path.

```bash
# From repos.yaml (batch)
vuln-hunter-x prepare
vuln-hunter-x prepare --repo libucl --lang c

# From a URL
vuln-hunter-x prepare --url https://github.com/org/repo.git --lang go
vuln-hunter-x prepare --url https://github.com/org/lib.git --lang c --build-command "make"

# From an existing local directory
vuln-hunter-x prepare --local-path /path/to/repo --lang python
```

| Option | Description |
|---|---|
| `--url URL` | Git URL to clone |
| `--local-path PATH` | Existing local directory |
| `--name NAME` | Repository name (auto-derived if omitted) |
| `--lang LANG` | Language — required with `--url` or `--local-path` |
| `--build-command CMD` | Build command for compiled languages |
| `--config PATH` | Path to repos.yaml |
| `--repo NAME` | Filter to one repository (config mode) |
| `--skip-db` | Skip CodeQL database creation |
| `--ask-llm` | Ask LLM for help if the build fails |
| `--dry-run` | Preview actions without executing |

---

### analyze

Run static analysis with CodeQL, Semgrep, and/or OpenGrep.

```bash
vuln-hunter-x analyze --repo libucl
vuln-hunter-x analyze --tool semgrep --repo pyyaml
vuln-hunter-x analyze --tool all --repo c-ares
vuln-hunter-x analyze --tool semgrep --local-path /path/to/project --lang python
```

| Option | Description | Default |
|---|---|---|
| `--tool {codeql,semgrep,opengrep,both,all}` | Analyzer(s) to run | `codeql` |
| `--local-path PATH` | Analyze a local directory | — |
| `--name NAME` | Repository name (auto-derived) | — |
| `--semgrep-config CONFIG` | Semgrep ruleset (repeatable) | `auto` |
| `--opengrep-config CONFIG` | OpenGrep ruleset (repeatable) | `auto` |
| `--codeql-suite SUITE` | CodeQL query suite | language default |
| `--repo NAME` | Filter to one repository | All |
| `--lang LANG` | Filter by language | All |
| `-j, --jobs N` | Parallel CodeQL analyses | 2 |
| `-f, --force` | Re-run even if SARIF exists | false |
| `--dry-run` | Preview | false |

---

### extract-context

Extract function/caller/struct context into CSVs for multi-turn verification.

```bash
vuln-hunter-x extract-context --repo libucl
vuln-hunter-x extract-context --local-path /path/to/project --lang go
```

| Option | Description | Default |
|---|---|---|
| `--local-path PATH` | Extract from a local directory | — |
| `--name NAME` | Repository name (auto-derived) | — |
| `--backend {auto,codeql,treesitter}` | Extraction backend | `auto` |
| `--repo NAME` | Filter to one repository | All |
| `--lang LANG` | Filter by language | All |
| `-f, --force` | Re-extract even if CSVs exist | false |

---

### verify

Verify SARIF findings using LLM multi-turn analysis.

```bash
vuln-hunter-x verify --repo libucl
vuln-hunter-x verify --repo c-ares --lang c --report
vuln-hunter-x verify --provider ollama --model ollama/llama3.2
vuln-hunter-x verify --local-path /path/to/project --lang python
```

| Option | Description | Default |
|---|---|---|
| `--local-path PATH` | Verify findings for a local directory | — |
| `--name NAME` | Repository name (auto-derived) | — |
| `--repo NAME` | Filter to one repository | All |
| `--lang LANG` | Filter by language | All |
| `--provider {openai,anthropic,ollama}` | LLM provider | From config |
| `--model MODEL` | Model name | From config |
| `--max-iterations N` | Max conversation rounds per finding | 3 |
| `--limit N` | Maximum findings to process | Unlimited |
| `--include-tests` | Include findings in test directories | false |
| `--report` | Generate a markdown report after verification | false |
| `-v, --verbose` | Show full LLM conversation | false |
| `-q, --quiet` | Minimal output | false |
| `--log-file PATH` | Save conversations to file | — |
| `--dry-run` | Preview findings | false |

---

### report

Generate a markdown report from verification results. Can be run standalone or triggered automatically with `verify --report`.

```bash
vuln-hunter-x report --repo c-ares --lang c
vuln-hunter-x report --results-dir output/c/c-ares/verification_results
vuln-hunter-x report --repo libucl -o my-report.md
```

| Option | Description |
|---|---|
| `--results-dir PATH` | Path to a `verification_results/` directory |
| `--repo NAME` | Repository name (auto-discovers results) |
| `--lang LANG` | Language (auto-discovers results) |
| `-o, --output PATH` | Output path (default: `report.md` in results dir) |

Report sections: executive summary · severity breakdown · CWE distribution · per-finding detail (verdict, confidence, reasoning, dataflow).

---

### Fuzz stages (C/C++ only)

```bash
vuln-hunter-x build-sanitized --repo libucl
vuln-hunter-x extract-fuzz-context --repo libucl
vuln-hunter-x generate-fuzz-drivers --repo libucl --build --llm-fix
vuln-hunter-x fuzz-run --repo libucl --triage
```

Full reference: [docs/fuzz_stages.md](docs/fuzz_stages.md).

---

### info

```bash
vuln-hunter-x info
```

Shows the active configuration (provider, model, paths).

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

## Configuration

### Environment variables (`.env`)

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `OLLAMA_API_BASE` | Ollama server URL |
| `LLM_PROVIDER` | Override default provider |
| `LLM_MODEL` | Override default model |
| `CODEQL_PATH` | Path to CodeQL CLI (if not on PATH) |
| `SEMGREP_PATH` | Path to Semgrep CLI (if not on PATH) |
| `OPENGREP_PATH` | Path to OpenGrep CLI (if not on PATH) |

### LLM / verification settings (`config/confirm_findings.yaml`)

```yaml
provider: openai          # openai | anthropic | ollama
model: gpt-4o
temperature: 0.2
max_tokens: 1500
max_iterations: 3         # conversation rounds per finding
```

Priority: CLI args > environment variables > config file > defaults.

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

  - name: my-go-app
    url: https://github.com/org/my-go-app.git
    language: go
```

| Field | Description |
|---|---|
| `name` | Short identifier used in output paths |
| `url` | Git clone URL |
| `language` | `c` · `cpp` · `python` · `javascript` · `php` · `java` · `go` |
| `build_command` | Required for C/C++; omit for interpreted languages |

### Guided questions (`config/prompts/`)

Rule-specific question sets that force the LLM to reason step-by-step before giving a verdict.

| File | Language | Rules |
|---|---|---|
| `cpp_questions.yaml` | C/C++ | 61 |
| `python_questions.yaml` | Python | 57 |
| `java_questions.yaml` | Java | 53 |
| `javascript_questions.yaml` | JavaScript | 53 |
| `php_questions.yaml` | PHP | 51 |
| `go_questions.yaml` | Go | 50 |
| `default_questions.yaml` | Fallback | 1 |

Coverage: SQL injection, XSS, command injection, path traversal, SSRF, deserialization, weak cryptography, access control, resource leaks, and more.

---

## Project Structure

```
VulnHunterX/
├── src/vuln_hunter_x/
│   ├── cli/           # CLI commands
│   ├── codeql/        # Database creation, analysis, context extraction
│   ├── context/       # Heuristic + tree-sitter context extraction
│   ├── core/          # Types, config, constants
│   ├── fuzz/          # Fuzz stages 5–8 (C/C++ only)
│   ├── llm/           # LLM client and prompt construction
│   ├── opengrep/      # OpenGrep integration
│   ├── questions/     # Guided questions loader
│   ├── reporting/     # Markdown report generation
│   ├── sarif/         # SARIF parsing
│   ├── semgrep/       # Semgrep integration
│   └── verification/  # Verification engine
├── config/
│   ├── confirm_findings.yaml  # LLM and verification settings
│   ├── repos.yaml             # Repository definitions
│   ├── prompts/               # Guided questions (7 languages)
│   └── queries/               # CodeQL context queries (6 languages)
├── benchmarks/        # Evaluation framework
├── examples/          # Per-language pipeline scripts
├── docs/              # Security check reference, fuzz stages
├── tests/
└── output/            # Per-repo stage outputs
    └── <lang>/<repo>/
        ├── database/              # CodeQL database
        ├── *.sarif                # SARIF results (CodeQL, Semgrep, OpenGrep)
        ├── context/               # Extracted CSVs
        ├── verification_results/  # Verdict JSON + report.md
        ├── sanitized_build/       # (C/C++) sanitizer build
        ├── fuzz_targets/          # (C/C++) harnesses
        └── fuzz_results/          # (C/C++) crashes
```

---

## Security Checks Documentation

- [C/C++ Security Checks](docs/codeql_cpp_security.md)
- [Python Security Checks](docs/codeql_python_security.md)
- [JavaScript Security Checks](docs/codeql_javascript_security.md)
- [CodeQL Overview](docs/codeql_security_checks.md)
- [Fuzz Stages](docs/fuzz_stages.md)

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/
ruff check src/
mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

---

## Benchmark

| Dataset | Size | Language |
|---|---|---|
| [SecLLMHolmes](https://github.com/ai4cloudops/SecLLMHolmes) | 228 findings | C/C++, Python |
| [Juliet C/C++](https://samate.nist.gov/SARD/) | 64K test cases | C/C++ |
| [CVEfixes](https://zenodo.org/records/13118970) | 12K commits | Multi-language |
| [DiverseVul](https://github.com/wagner-group/diversevul) | 349K functions | C/C++ |

```bash
python benchmarks/scripts/setup_datasets.py --dataset secllmholmes
python benchmarks/scripts/run_benchmark.py --dataset secllmholmes --approach all --limit 50
python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/<run_dir>
```

Approaches: `raw-sast` (baseline) · `single-shot` · `generic-questions` · `vulnhunterx` (full pipeline).

---

## License

MIT

---

## References

- [Vulnhalla — CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack) — original methodology
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
