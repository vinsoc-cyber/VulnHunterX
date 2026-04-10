# VulnHunterX

**SAST (CodeQL, Semgrep, OpenGrep) + fuzzing + LLM vulnerability hunting and verification**

A Python framework that combines static analysis with LLM verification to reduce false positives in security findings. Implements the Vulnhalla methodology for intelligent, multi-turn bug confirmation.

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

Static analysis tools (CodeQL, Semgrep, OpenGrep) produce many findings, but a significant portion are **false positives**. This framework automates triage by using LLMs to analyze code context, answer rule-specific guided questions, request additional context when needed (multi-turn), and provide verdicts with confidence levels and reasoning.

### Key Features

| Feature | Description |
|---|---|
| **Multi-language** | C, C++, Python, JavaScript, PHP, Java, Go |
| **LLM verification** | Multi-turn with dynamic context expansion |
| **Guided questions** | 300+ rule-specific question templates across 7 languages |
| **Context expansion** | LLM can request callers, structs, globals, typedefs, enums |
| **Multiple LLM providers** | OpenAI (GPT-4), Anthropic (Claude), Ollama (local) |
| **Multi SAST** | CodeQL, Semgrep, OpenGrep (`--tool codeql\|semgrep\|opengrep\|both\|all`) |
| **Direct clone** | Clone from URL or use local directory (`--url`, `--local-path`) |
| **Tree-sitter fallback** | Source-based context extraction when CodeQL is unavailable |
| **Markdown reports** | Generate human-readable reports from verification results |
| **Fuzz confirmation** | libFuzzer harness generation + crash triage (C/C++) |
| **Benchmarking** | Precision/recall across 4 ground-truth datasets |

### How It Works

```
Source repo  ──>  Static Analysis  ──>  SARIF Findings  ──>  LLM Verification  ──>  Verdicts
(clone)           (CodeQL/Semgrep/      (rule, file,          (guided questions,      (TP/FP/NMD +
                   OpenGrep)             line, severity)       multi-turn context)     confidence)
```

The **Vulnhalla methodology** improves accuracy through:
- **Rule-specific questions** — each finding type gets tailored questions
- **Multi-turn conversation** — the LLM can reason across several steps
- **Dynamic context expansion** — the LLM can request callers, structs, globals before deciding

---

## Quick Start

```bash
# Install
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .

# Configure
cp env.example .env   # Edit: add OPENAI_API_KEY or ANTHROPIC_API_KEY

# Verify environment
vuln-hunter-x check-env

# Run pipeline
vuln-hunter-x clone --repo pyyaml
vuln-hunter-x analyze --repo pyyaml
vuln-hunter-x verify --repo pyyaml --limit 5 --report
```

**For detailed setup**, see [QUICKSTART.md](QUICKSTART.md).

---

## Pipeline Stages

| Stage | Command | Input | Output |
|---|---|---|---|
| 1 | `clone` | Repository URL / local path | Source code + CodeQL database |
| 2 | `analyze` | CodeQL DB and/or source | SARIF findings |
| 3 | `extract-context` | CodeQL DB / source | CSV context files |
| 4 | `verify` | SARIF + CSVs | JSON verdicts (+ optional markdown report) |
| 5-8 | `build-sanitized` / `extract-fuzz-context` / `generate-fuzz-drivers` / `fuzz-run` | C/C++ only | Fuzz harnesses + crash results |

| Goal | Required | Optional |
|---|---|---|
| Static analysis only | 1, 2 | - |
| LLM verification | 1, 2, 4 | 3 (richer multi-turn context) |
| Fuzz confirmation (C/C++) | 1, 2, 4, 5, 6, 7 | 3, 8 |

**SAST tools:** CodeQL requires building a database (stage 1); Semgrep and OpenGrep scan source directly. All produce SARIF; the verify stage reads all SARIF files. See [docs/fuzz_stages.md](docs/fuzz_stages.md) for stages 5-8.

---

## CLI Reference

```
vuln-hunter-x <command> [options]
```

### check-env

Check prerequisites: CodeQL CLI, Semgrep/OpenGrep (optional), LLM provider keys.

```bash
vuln-hunter-x check-env
```

### clone

Clone repositories and create CodeQL databases. Supports three modes: config file, direct URL, or local path.

```bash
# Config mode (default) — from repos.yaml
vuln-hunter-x clone
vuln-hunter-x clone --repo libucl --lang c

# Direct URL mode — no repos.yaml needed
vuln-hunter-x clone --url https://github.com/org/repo.git --lang go
vuln-hunter-x clone --url https://github.com/org/lib.git --lang c --name mylib --build-command "make"

# Local path mode — use existing directory
vuln-hunter-x clone --local-path /path/to/repo --lang python --name my-project
```

| Option | Description |
|---|---|
| `--config PATH` | Path to repos.yaml |
| `--url URL` | Git URL (direct clone, no repos.yaml) |
| `--local-path PATH` | Existing local directory |
| `--name NAME` | Repository name (auto-derived from URL/path if omitted) |
| `--build-command CMD` | Build command for compiled languages |
| `--lang LANG` | Language (required with `--url` or `--local-path`) |
| `--repo NAME` | Filter by repository (config mode) |
| `--skip-db` | Clone only, skip database creation |
| `--ask-llm` | Ask LLM for help if build fails |
| `--dry-run` | Preview without executing |

### analyze

Run CodeQL, Semgrep, and/or OpenGrep analysis.

```bash
vuln-hunter-x analyze --repo libucl -v
vuln-hunter-x analyze --tool semgrep --repo pyyaml
vuln-hunter-x analyze --tool all --repo c-ares
```

| Option | Description | Default |
|---|---|---|
| `--tool {codeql,semgrep,opengrep,both,all}` | Analyzer(s) to run | codeql |
| `--semgrep-config CONFIG` | Semgrep config (repeatable) | auto |
| `--opengrep-config CONFIG` | OpenGrep config (repeatable) | auto |
| `--codeql-suite SUITE` | CodeQL query suite | language default |
| `--repo NAME` | Specific repository | All |
| `--lang LANG` | Filter by language | All |
| `-j, --jobs N` | Parallel CodeQL analyses | 2 |
| `-f, --force` | Re-run even if SARIF exists | false |
| `--dry-run` | Preview | false |

### extract-context

Extract context CSVs (functions, callers, structs, globals) for multi-turn verification.

```bash
vuln-hunter-x extract-context --repo libucl
vuln-hunter-x extract-context --backend treesitter  # When no CodeQL DB
```

| Option | Description | Default |
|---|---|---|
| `--backend {auto,codeql,treesitter}` | Extraction backend | auto |
| `--repo NAME` | Specific repository | All |
| `-f, --force` | Re-extract | false |

### verify

Verify findings using LLM analysis.

```bash
vuln-hunter-x verify --repo libucl
vuln-hunter-x verify --repo c-ares --lang c --report
vuln-hunter-x verify --provider ollama --model ollama/llama3.2
vuln-hunter-x verify --limit 5 -v --log-file output/conversations.md
```

| Option | Description | Default |
|---|---|---|
| `--repo NAME` | Specific repository | All |
| `--lang LANG` | Filter by language | All |
| `--provider {openai,anthropic,ollama}` | LLM provider | From config |
| `--model MODEL` | Model name | From config |
| `--max-iterations N` | Max conversation rounds | 3 |
| `--limit N` | Max findings | Unlimited |
| `--include-tests` | Include findings in test/ directories | false |
| `--report` | Generate markdown report after verification | false |
| `-v, --verbose` | Detailed LLM output | false |
| `-q, --quiet` | Minimal output | false |
| `--dry-run` | Preview findings | false |

### report

Generate markdown report from existing verification results.

```bash
vuln-hunter-x report --repo c-ares --lang c
vuln-hunter-x report --results-dir output/c/c-ares/verification_results
vuln-hunter-x report --repo libucl -o my-report.md
```

| Option | Description |
|---|---|
| `--results-dir PATH` | Path to verification_results directory |
| `--repo NAME` | Repository name (auto-discover results) |
| `--lang LANG` | Language (auto-discover results) |
| `-o, --output PATH` | Output path (default: report.md in results dir) |

**Report includes:** executive summary, severity breakdown, CWE distribution, per-finding detail (verdict, confidence, reasoning, dataflow).

### Fuzz stages (C/C++ only)

See [docs/fuzz_stages.md](docs/fuzz_stages.md) for full reference.

```bash
vuln-hunter-x build-sanitized --repo libucl
vuln-hunter-x extract-fuzz-context --repo libucl
vuln-hunter-x generate-fuzz-drivers --repo libucl --build --llm-fix
vuln-hunter-x fuzz-run --repo libucl --triage
```

### info

Show current configuration.

```bash
vuln-hunter-x info
```

---

## Python API

```python
from vuln_hunter_x import VerificationEngine

engine = VerificationEngine.from_config("config/confirm_findings.yaml")

# Verify a SARIF file
result = engine.verify_sarif("output/c/libucl/libucl.sarif", lang="c", repo_name="libucl")

for verdict in result.verdicts:
    print(f"{verdict.finding.rule_id}: {verdict.verdict} ({verdict.confidence})")

# Save results
engine.save_results(result)

# Generate report
from vuln_hunter_x.reporting.markdown import MarkdownReportGenerator
generator = MarkdownReportGenerator()
generator.generate(result, Path("output/c/libucl/verification_results/report.md"))
```

---

## Configuration

### Environment Variables (`.env`)

| Variable | Description | Required |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key | For OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic API key | For Claude |
| `OLLAMA_API_BASE` | Ollama server URL | For Ollama |
| `LLM_PROVIDER` | Default provider | Override config |
| `LLM_MODEL` | Default model | Override config |
| `CODEQL_PATH` | CodeQL CLI path | If not on PATH |
| `SEMGREP_PATH` | Semgrep CLI path | If not on PATH |
| `OPENGREP_PATH` | OpenGrep CLI path | If not on PATH |

### Application Settings (`config/confirm_findings.yaml`)

```yaml
provider: openai          # openai, anthropic, or ollama
model: gpt-4o
temperature: 0.2
max_tokens: 1500
max_iterations: 3         # Max conversation rounds per finding
```

**Priority order:** CLI args > environment variables > config file > defaults.

### Repository Definitions (`config/repos.yaml`)

```yaml
repos:
  - name: minimist
    url: https://github.com/minimistjs/minimist.git
    language: javascript

  - name: libucl
    url: https://github.com/vstakhov/libucl.git
    language: c
    build_command: "mkdir -p build && cd build && cmake .. && make"

  - name: go-vuln
    url: https://github.com/golang/vuln.git
    language: go
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Short name (used in paths) |
| `url` | Yes | Git clone URL |
| `language` | Yes | `c`, `cpp`, `python`, `javascript`, `php`, `java`, `go` |
| `build_command` | C/C++ only | Shell build command |

### Guided Questions (`config/prompts/`)

Rule-specific questions that force the LLM to reason step-by-step. Based on the Vulnhalla methodology.

```
config/prompts/
├── system_prompt.yaml        # LLM system prompt template
├── default_questions.yaml    # Fallback for unknown rules
├── cpp_questions.yaml        # C/C++ (61 rules)
├── python_questions.yaml     # Python (57 rules)
├── go_questions.yaml         # Go (50 rules)
├── java_questions.yaml       # Java (53 rules)
├── javascript_questions.yaml # JavaScript (53 rules)
└── php_questions.yaml        # PHP (51 rules)
```

**Total: 325+ rules** covering SQL injection, XSS, command injection, path traversal, SSRF, deserialization, cryptographic weaknesses, access control, resource leaks, and many more.

### CodeQL Tool Queries (`config/queries/tools/`)

Custom queries that extract structured context for multi-turn verification.

```
config/queries/tools/
├── cpp/       # functions, callers, structs, globals, macros
├── python/    # functions, callers, classes
├── javascript/# functions, callers, classes
├── java/      # functions, callers, classes
├── php/       # functions, callers, classes
└── go/        # functions, callers, classes
```

---

## Project Structure

```
VulnHunterX/
├── src/vuln_hunter_x/
│   ├── cli/           # CLI commands and argument parsing
│   ├── codeql/        # CodeQL database, analysis, context extraction
│   ├── context/       # Heuristic + tree-sitter context extraction
│   ├── core/          # Types, config, constants
│   ├── fuzz/          # Fuzz stages 5-8 (C/C++ only)
│   ├── llm/           # LLM client and prompt construction
│   ├── opengrep/      # OpenGrep integration
│   ├── questions/     # Guided questions loader
│   ├── reporting/     # Markdown report generation
│   ├── sarif/         # SARIF parsing
│   ├── semgrep/       # Semgrep integration
│   └── verification/  # Verification engine
├── config/
│   ├── confirm_findings.yaml
│   ├── repos.yaml
│   ├── prompts/       # Guided questions (7 languages + defaults)
│   └── queries/       # CodeQL tool queries (6 languages)
├── benchmarks/        # Precision/recall evaluation framework
├── examples/          # Pipeline examples (C, C++, Python, JS, Java, PHP)
├── docs/              # Security check docs, fuzz stages
├── tests/             # Test suite
└── output/            # All stage outputs (per lang/repo)
    └── <lang>/<repo>/
        ├── database/              # CodeQL database
        ├── <repo>.sarif           # CodeQL SARIF
        ├── <repo>_semgrep.sarif   # Semgrep SARIF (if run)
        ├── <repo>_opengrep.sarif  # OpenGrep SARIF (if run)
        ├── context/               # Extracted CSVs
        ├── verification_results/  # Verdict JSONs + summary + report.md
        ├── sanitized_build/       # Sanitized build (C/C++)
        ├── fuzz_targets/          # Harness .cc + status.json (C/C++)
        └── fuzz_results/          # Crashes + summary (C/C++)
```

---

## Security Checks Documentation

- [C/C++ Security Checks](docs/codeql_cpp_security.md)
- [Python Security Checks](docs/codeql_python_security.md)
- [JavaScript Security Checks](docs/codeql_javascript_security.md)
- [CodeQL Overview](docs/codeql_security_checks.md)
- [Fuzz Stages](docs/fuzz_stages.md)
- [Guided Questions Research](docs/guided_questions_research.md)

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/
ruff check src/
mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## Benchmark

VulnHunterX includes a benchmarking framework to measure false-positive reduction accuracy.

| Dataset | Size | Language | Source |
|---|---|---|---|
| **SecLLMHolmes** | 228 findings | C/C++, Python | [GitHub](https://github.com/ai4cloudops/SecLLMHolmes) |
| **Juliet C/C++** | 64K test cases | C/C++ | [NIST SARD](https://samate.nist.gov/SARD/) |
| **CVEfixes** | 12K commits | Multi-language | [Zenodo](https://zenodo.org/records/13118970) |
| **DiverseVul** | 349K functions | C/C++ | [GitHub](https://github.com/wagner-group/diversevul) |

```bash
# Setup
python benchmarks/scripts/setup_datasets.py --dataset secllmholmes

# Run
python benchmarks/scripts/run_benchmark.py --dataset secllmholmes --approach all --limit 50

# Report
python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/<run_dir>
```

| Approach | Description |
|---|---|
| `raw-sast` | Baseline: accept all SAST findings (no LLM) |
| `single-shot` | Single LLM call, no guided questions |
| `generic-questions` | Multi-turn with generic questions |
| `vulnhunterx` | Full pipeline with rule-specific questions |

---

## License

MIT License

---

## References

- [Vulnhalla - CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack) - Original methodology
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [SecLLMHolmes](https://github.com/ai4cloudops/SecLLMHolmes) - LLM vulnerability detection benchmark
- [DiverseVul](https://github.com/wagner-group/diversevul) - 349K C/C++ functions (RAID 2023)
- [Juliet Test Suite](https://samate.nist.gov/SARD/) - NIST SARD synthetic test cases
- [CVEfixes](https://zenodo.org/records/13118970) - Vulnerability-fixing commits dataset
