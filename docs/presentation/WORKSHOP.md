# VulnHunterX Workshop — Copy-Paste Handout

A 60-minute hands-on guide. Run everything from the repo root with your
virtualenv activated. **Windows users: do all of this inside WSL2 or a Linux
Docker container** (`wsl --install`, then open Ubuntu).

---

## 0. Setup (do this before the workshop)

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"          # or: python3.12 -m venv .venv && pip install -e ".[dev]"

cp env.example .env                 # edit: OPENAI_API_KEY / ANTHROPIC_API_KEY / OLLAMA_API_BASE
vuln-hunter-x check-env             # everything should report OK
```

Prerequisites: Python 3.12+, [CodeQL CLI 2.15+](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/),
an LLM provider (OpenAI / Anthropic / local Ollama). Semgrep/OpenGrep are optional.

---

## Exercise E1 — Get a green toolchain

```bash
vuln-hunter-x check-env
```

Fix anything red:

| Symptom | Fix |
|---|---|
| `CodeQL CLI not found` | Add to `PATH` or set `CODEQL_PATH` in `.env` |
| `Semgrep CLI not found` | Set `SEMGREP_PATH` in `.env` (or skip `--tool semgrep`) |
| `OpenAI API key not configured` | Add `OPENAI_API_KEY=sk-...` to `.env` |

---

## Exercise E2 — Your first scan, then read the report

```bash
# Smoke-test the wiring (no LLM calls):
python examples/pipeline_python.py --dry-run

# Real run, small + cheap:
vuln-hunter-x scan --repo pyyaml --tool both --profile extended --limit 3

# Read it:
cat output/python/pyyaml/verification_results/report.md
```

Find **one True Positive** and **one False Positive** in the report. Note the
confidence and the reasoning the LLM gave.

> Friendlier alternative: `vuln-hunter-x interactive` walks you through every option.

---

## Exercise E3 — Iterations matter

```bash
vuln-hunter-x verify --repo pyyaml --max-iterations 5 --limit 3
```

Compare verdicts and confidence against the default (`--max-iterations 3`). More
turns let the LLM pull more context before deciding — watch a "Needs More Data"
become a confident verdict.

---

## Exercise E4 — Another language

```bash
python examples/pipeline_go.py            # gin (real) vs a gosec baseline (vuln)
# or pipeline_java.py / pipeline_php.py / pipeline_javascript.py
cat output/go/gin/verification_results/report.md
```

---

## Homework

```bash
# H1 — scan your own repo
vuln-hunter-x scan --local-path /path/to/your/repo --lang <lang> --profile full --limit 10

# H2 — compare two providers on the same findings
vuln-hunter-x verify --repo pyyaml --provider openai  --model gpt-4o        --limit 5
vuln-hunter-x verify --repo pyyaml --provider ollama  --model ollama/llama3.2 --limit 5

# H3 — write a custom Semgrep rule, then verify it's wired up
#   edit config/semgrep-custom/<lang>.yaml  (set metadata.cwe: ["CWE-NNN"])
vuln-hunter-x analyze --repo pyyaml --profile full        # custom rules only fire under `full`
python scripts/audit_rule_coverage.py --fail-on-gaps

# H4 — stretch (Linux/macOS only): fuzz a C target
vuln-hunter-x build-sanitized       --repo libucl
vuln-hunter-x extract-fuzz-context  --repo libucl
vuln-hunter-x generate-fuzz-drivers --repo libucl --build --llm-fix
vuln-hunter-x fuzz-run              --repo libucl --triage
```

---

## Cheat sheet

| Command | What it does |
|---|---|
| `vuln-hunter-x interactive` | Guided wizard — friendliest entry point |
| `vuln-hunter-x scan ...` | Full pipeline (prepare → analyze → verify → report) |
| `vuln-hunter-x prepare ...` | Clone + CodeQL DB + context CSVs |
| `vuln-hunter-x analyze ...` | Run CodeQL/Semgrep/OpenGrep → SARIF |
| `vuln-hunter-x verify ...` | LLM triage of SARIF → verdicts |
| `vuln-hunter-x report ...` | Regenerate the markdown report |
| `vuln-hunter-x check-env` | Verify the toolchain |
| `vuln-hunter-x info` | Print resolved config |

Common flags: `--tool {codeql,semgrep,opengrep,both,all}`,
`--profile {standard,extended,maximum,extended-registry,full}`,
`--provider`, `--model`, `--limit N`, `--max-iterations N`, `-j/--jobs N`,
`--dry-run`.
