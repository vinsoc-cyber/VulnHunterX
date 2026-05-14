# VulnHunterX Benchmarks

Standalone benchmark framework comparing VulnHunterX against baselines on six ground-truth datasets. Runs as plain Python scripts from the repo root — no separate installation.

---

## Table of Contents

- [What it does](#what-it-does)
- [Approaches](#approaches)
- [Datasets](#datasets)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Per-Dataset Playbooks](#per-dataset-playbooks)
- [CLI Reference](#cli-reference)
- [Metrics](#metrics)
- [Output Structure](#output-structure)
- [Interpreting Results](#interpreting-results)
- [Resuming Interrupted Runs](#resuming-interrupted-runs)
- [Adding Datasets or Approaches](#adding-datasets-or-approaches)

---

## What it does

For each (dataset, approach) pair the harness produces a verdict per entry, scores it against ground truth, and emits precision / recall / F1, FP-reduction rate, NMD rate, mean tokens-per-finding, p95 latency, and confidence-calibration tables. Results are checkpointed per entry and can be resumed after Ctrl+C or process death.

The design rationale, papers reviewed, and dataset selection criteria are in [RESEARCH.md](RESEARCH.md).

---

## Approaches

| Approach      | What it does                                                                                                                |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `raw-sast`    | Every SAST finding is treated as TP, no LLM call. Establishes upper-bound recall and reveals the underlying FP rate.        |
| `vulnhunterx` | Full pipeline: rule-specific guided questions + answer-before-verdict + multi-turn context expansion.                       |
| `ablation`    | Runs each entry through three internal variants — *zero-shot*, *generic-questions*, *rule-specific* — to isolate the contribution of guided-question authorship vs. the protocol itself. |
| `all`         | Shorthand for `raw-sast vulnhunterx ablation`.                                                                              |

---

## Datasets

| Dataset                  | Size           | Language       | Ground Truth                                                                                |
| ------------------------ | -------------- | -------------- | ------------------------------------------------------------------------------------------- |
| **SecLLMHolmes**         | ~228 scenarios | C/C++, Python  | Handcrafted bad/good pairs, 8 CWE classes (MIT)                                             |
| **Juliet C/C++ 1.3.1**   | 64K cases      | C, C++         | NIST synthetic `bad()`/`good()` function pairs, ~180 CWEs                                   |
| **DiverseVul**           | 349K functions | C, C++         | 18,945 CVE-backed vulnerable + 330,492 non-vulnerable (CWE-Unknown rows dropped by default — see playbook) |
| **OWASP BenchmarkJava**  | ~2,740 cases   | Java           | `expectedresults-1.2.csv` (TP/FP per case, 11 CWE categories) — GPL-2.0                     |
| **OWASP BenchmarkPython**| ~1,230 cases   | Python         | `expectedresults-0.1.csv` — GPL-3.0                                                         |
| **RealVuln Benchmark**   | 796 findings   | Python         | Real CVE TPs + curated FP traps across 26 web-framework repos (Flask/Django/FastAPI/aiohttp/Tornado) — MIT |

OWASP suites are cloned at runtime under `benchmarks/datasets/` rather than vendored; project code stays MIT and the GPL applies only to the cloned corpora. See [RESEARCH.md § Future Work](RESEARCH.md#planned-future-work) for the SastBench → RealVuln substitution rationale.

---

## Prerequisites

- Python 3.12+ with VulnHunterX installed (`uv pip install -e .`)
- For LLM approaches: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or a local Ollama instance
- For chart generation: `uv pip install -e ".[benchmark]"`
- Disk: ~650 MB for SecLLMHolmes + Juliet, ~2 GB more for DiverseVul, ~50 MB each for OWASP/RealVuln
- CodeQL CLI (optional; only needed for Juliet "full" mode)

---

## Quick Start

### 1. Smoke test — no LLM, no dataset download

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach raw-sast --limit 10
# Uses the 10-entry fixture under benchmarks/fixtures/, completes in <5 s.
```

### 2. Dry-run — mock LLM, exercises every code path

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all --limit 20 --dry-run
```

### 3. Download datasets

```bash
python benchmarks/scripts/setup_datasets.py --list             # list available
python benchmarks/scripts/setup_datasets.py --dataset secllmholmes   # single (~50 MB)
python benchmarks/scripts/setup_datasets.py --dataset all      # everything (~3 GB)
```

### 4. Small real run

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all \
    --model gpt-4o-mini --limit 50
```

### 5. Generate the report

```bash
python benchmarks/scripts/generate_report.py \
    --run-dir benchmarks/results/<timestamp>
# Add --charts to render precision/recall plots (requires matplotlib).
```

### 6. Full benchmark

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o
```

### 7. Iteration sweep (measure multi-turn contribution)

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach vulnhunterx \
    --model gpt-4o-mini --iteration-sweep
# Runs at max_iterations = 1, 2, 3.
```

### 8. Resumable run — survive Ctrl+C

```bash
# Start with an explicit named directory:
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run

# Resume after an interruption:
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run --resume
```

### Dataset size tiers

Starting points for `--limit` and dataset-specific flags:

| Dataset    | Small                        | Medium                        | Large                              |
| ---------- | ---------------------------- | ----------------------------- | ---------------------------------- |
| SecLLMHolmes | `--limit 20`               | `--limit 100`                 | `--limit 0` (all, ~228)            |
| Juliet     | `--juliet-per-cwe 5` (~40)   | `--juliet-per-cwe 20` (~160)  | `--juliet-per-cwe 0` (~64K)        |
| DiverseVul | `--limit 500`                | `--limit 5000`                | `--limit 0` (~349K)                |

For runs over a few thousand entries, use a local Ollama model — commercial-API cost grows quickly. See [RESEARCH.md § Token / Cost Reference](RESEARCH.md#token-and-cost-reference).

### Parallel evaluation (`-j, --jobs`)

Benchmark runs are I/O-bound on the LLM provider, so the runner evaluates entries concurrently with a `ThreadPoolExecutor`. Default `--jobs 4` typically yields ~3–4× wall-clock speedup over sequential mode.

```bash
# Default — 4 entries in flight at a time
python benchmarks/scripts/run_benchmark.py --dataset owasp --approach vulnhunterx

# Push harder on high-tier API keys or a self-hosted Ollama
python benchmarks/scripts/run_benchmark.py --dataset diversevul --approach vulnhunterx -j 16

# Strict sequential for debugging (clean stack traces, deterministic logs)
python benchmarks/scripts/run_benchmark.py --dataset secllmholmes --approach vulnhunterx -j 1
```

Notes:
- The `vulnhunterx` approach pins the inner `VerificationEngine` to `jobs=1` so only the outer benchmark layer fans out — no hidden double-parallelism.
- Per-entry order in `findings.jsonl` and the per-approach results JSON is preserved (entries finish concurrently but slot into their input index), so resume semantics are unaffected.
- On free/low-tier OpenAI keys, `-j 4` can surface 429 rate-limit errors; drop to `-j 1` or `-j 2` if you see those.
- Progress display and per-entry log lines are serialized — output still reads top-to-bottom.

---

## Per-Dataset Playbooks

### Juliet C/C++

Synthetic, balanced TP/FP pairs per CWE. `--juliet-per-cwe` controls scale.

```bash
# Small sanity check — ~40 entries
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach vulnhunterx \
    --juliet-per-cwe 5 --model gpt-4o-mini --dry-run

# Standard run — 8 BENCHMARK_CWES × 20 entries, balanced TP/FP
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach all \
    --juliet-per-cwe 20 --model gpt-4o-mini

# Full Juliet — local model strongly recommended
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach vulnhunterx \
    --juliet-per-cwe 0 --model ollama/llama3.2 \
    --run-dir benchmarks/results/juliet_full

# Multi-turn iteration sweep
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach vulnhunterx \
    --juliet-per-cwe 10 --model gpt-4o-mini --iteration-sweep
```

### DiverseVul

Real-world C/C++ functions with CVE-backed labels. Use `--limit` for scale and `--cwe` to target specific classes.

When running through a low-RPM LLM proxy, leave `--llm-concurrency` at the default (4) even if you crank `--jobs` higher — DiverseVul fans out fast enough that 30 simultaneous model calls will exhaust a quota in seconds. LiteLLM also retries 429/transient failures automatically (`llm.num_retries`, default 5).

By default, records whose source CVE has no CWE mapping are **dropped at load time**. These entries would otherwise land in a meaningless `"Unknown"` per-CWE bucket and force VulnHunterX into its generic-questions fallback, biasing the rule-specific ablation. Pass `--include-unknown-cwe` if you need the full corpus for binary classification only — the loader logs the dropped count either way.

```bash
# Targeted memory-safety dry-run
python benchmarks/scripts/run_benchmark.py \
    --dataset diversevul --approach vulnhunterx \
    --limit 500 --cwe CWE-787 CWE-416 --dry-run

# Medium run, all CWEs
python benchmarks/scripts/run_benchmark.py \
    --dataset diversevul --approach vulnhunterx \
    --limit 5000 --model gpt-4o-mini

# Full dataset — local model only
python benchmarks/scripts/run_benchmark.py \
    --dataset diversevul --approach vulnhunterx \
    --limit 0 --model ollama/llama3.2 \
    --run-dir benchmarks/results/diversevul_full

# Per-CWE sweep
for cwe in CWE-787 CWE-416 CWE-476 CWE-125; do
  python benchmarks/scripts/run_benchmark.py \
      --dataset diversevul --approach vulnhunterx \
      --limit 500 --cwe $cwe \
      --run-dir benchmarks/results/diversevul_$cwe
done
```

### OWASP Benchmark (Java + Python)

Two SAST test suites maintained by the OWASP Benchmark Project, each with CSV ground truth (`expectedresults-*.csv`). Each test case is a single file with a known TP/FP label and CWE — designed for SAST comparison.

```bash
# Smoke test (no LLM, fixture only)
python benchmarks/scripts/run_benchmark.py \
    --dataset owasp --approach raw-sast --limit 5

# Clone the suites
python benchmarks/scripts/setup_datasets.py --dataset owasp-java
python benchmarks/scripts/setup_datasets.py --dataset owasp-python

# Java only
python benchmarks/scripts/run_benchmark.py \
    --dataset owasp-java --approach all --model gpt-4o-mini \
    --run-dir benchmarks/results/owasp_java

# Java + Python combined (--dataset owasp runs both suites sequentially)
python benchmarks/scripts/run_benchmark.py \
    --dataset owasp --approach vulnhunterx --model gpt-4o-mini
```

Use `--dataset owasp-java` or `--dataset owasp-python` to run one suite individually. `--dataset owasp` runs both.

### RealVuln Benchmark

Real CVE true-positives + curated false-positive traps across 26 Python web-framework repos. Currently Python-only (Flask / Django / FastAPI / aiohttp / Tornado), 796 findings.

```bash
# Smoke test (no LLM, fixture only)
python benchmarks/scripts/run_benchmark.py \
    --dataset realvuln --approach raw-sast --limit 5

# Clone the suite
python benchmarks/scripts/setup_datasets.py --dataset realvuln

# Real run with a small model
python benchmarks/scripts/run_benchmark.py \
    --dataset realvuln --approach all --model gpt-4o-mini \
    --run-dir benchmarks/results/realvuln
```

For meaningful `code_snippet` content the adapter reads each function from a working tree at `benchmarks/datasets/realvuln/_repos/<repo_id>/`. You are responsible for checking out the matching `commit_sha` (recorded per finding) into that path. When the working tree is absent the snippet is left empty and tagged `metadata.snippet_kind = "missing"` — the entry still scores for `raw-sast` comparison, but downstream LLM approaches need the source.

---

## CLI Reference

### `run_benchmark.py`

```
--dataset           secllmholmes | juliet | diversevul |
                    owasp-java | owasp-python | owasp |
                    realvuln |
                    all  (default: secllmholmes)
                    `owasp` runs both OWASP Java + Python; `all` runs every dataset.
--approach          One or more of: raw-sast vulnhunterx ablation all  (default: all)
--model             LLM model name  (default: LLM_MODEL from .env, fallback gpt-4o)
--provider          openai | anthropic | ollama  (default: LLM_PROVIDER from .env)
--limit N           Max entries per dataset, 0=all  (default: 0)
--lang LANG [...]   Filter fixture entries by language: c cpp python javascript php java go
--cwe CWE [...]     DiverseVul only: filter by CWE ID(s), e.g. CWE-787 CWE-416
--include-unknown-cwe  DiverseVul only: keep records with no CWE mapping (off by default)
--juliet-per-cwe N  Juliet only: max entries per CWE, balanced TP/FP.
                    5=small (~40)  20=standard (~160) [default]  0=all CWEs (~64K)
--max-iterations N  Multi-turn rounds for vulnhunterx/generic  (default: 10)
--nmd-handling      exclude | fp  (default: exclude)
--dry-run           Mock LLM responses — no API cost
--resume            Skip completed pairs; continue in-progress pairs from last checkpoint
--run-dir PATH      Explicit output directory (use with --resume for recovery)
--run-id ID         Timestamp alias for --run-dir (e.g. 20260305_113225)
--checkpoint-every N  Incremental checkpoint every N entries (default: 1)
-j, --jobs N        Concurrent entries to evaluate (default: 4; set 1 to disable parallelism)
--llm-concurrency N Cap concurrent in-flight LLM calls (default: 4; 0 disables).
                    Independent of --jobs — threads still fan out at --jobs, but
                    the model call is gated so rate-limited proxies don't 429.
--verbose / -v      Detailed line per entry
--quiet             Suppress progress display; log lines only
--iteration-sweep   Run vulnhunterx at iterations = 1, 2, 3
```

### `setup_datasets.py`

```
--dataset  secllmholmes | juliet | diversevul |
           owasp-java | owasp-python | realvuln |
           all  (default: all)
--list     List available datasets and exit
```

### `generate_report.py`

```
--run-dir  Path to benchmark run directory  (required)
--charts   Generate matplotlib precision/recall charts
```

---

## Metrics

| Metric                     | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| **Precision**              | Of findings predicted TP, how many are actually vulnerable?        |
| **Recall**                 | Of all truly vulnerable findings, how many did we catch?           |
| **Effective Recall**       | Recall that counts NMDs on TPs as misses — see [RESEARCH.md § 2.5](RESEARCH.md#25-effective-recall-metric) |
| **F1**                     | Harmonic mean of precision and recall                              |
| **FP Reduction Rate**      | (raw-SAST FPs − approach FPs) / raw-SAST FPs                       |
| **TP Preservation Rate**   | approach TPs / raw-SAST TPs (must stay high)                       |
| **NMD Rate**               | Fraction returning "Needs More Data" (excluded from P/R/F1 by default) |
| **Confidence Calibration** | Within each confidence bucket, what % of predictions were correct? |
| **Tokens/Finding**         | Mean LLM tokens consumed per finding                               |
| **Latency p95**            | 95th-percentile wall-clock time per finding                        |

BENIGN entries (clean code not flagged by SAST) are tracked for cost/latency but excluded from precision/recall computation.

---

## Output Structure

```
benchmarks/results/<timestamp>/
├── summary.json                        # All metrics in one file
├── secllmholmes_raw-sast_results.json  # Per-approach checkpoints
├── secllmholmes_vulnhunterx_results.json
├── ...
├── REPORT.md                           # Human-readable report
├── benchmark.log                       # Full DEBUG/INFO log
├── findings.jsonl                      # One structured record per entry
└── precision_recall.png                # Chart (when --charts is set)
```

---

## Interpreting Results

**Good result for VulnHunterX:**

- `raw-sast`: recall = 100% by definition; precision ≈ 40% (typical SAST noise).
- `vulnhunterx`: precision > 80%, recall > 85%.
- FP reduction rate > 50% — eliminates more than half of raw-SAST false positives.
- High-confidence predictions are > 90% accurate (calibration).

**Warning signs:**

- TP preservation rate < 80% → VulnHunterX is suppressing real bugs.
- NMD rate > 30% → LLM is not getting enough context to decide.
- Calibration flat across High/Medium/Low → confidence scores are noise.
- `pred_api_error_count` > 0 in summary.json → some entries failed with an LLM API error (quota, rate-limit, network). REPORT.md surfaces this as a separate "LLM API failures" warning so it isn't conflated with model error. Re-run the affected entries with credit available before drawing conclusions about the methodology.

### Snippet-only context — known ceilings

Benchmark mode runs each entry against an in-memory code snippet only (no repo-wide context provider — see `_SnippetContextExtractor` in `benchmarks/approaches/base.py`). For most CWEs (injection, XSS, path traversal) the immediate snippet contains the source-to-sink flow and recall stays ≥90%. Two CWEs hit a hard floor because the deciding signal lives outside the snippet:

- **CWE-328 (weak hashing)** — OWASP BenchmarkJava loads the algorithm name from `BenchmarkRunner.properties`; the snippet only shows `MessageDigest.getInstance(algo)` with no way to tell whether `algo` is `MD5` or `SHA-512`. The LLM correctly answers "no exploitable use" for the safe-default branch and gets graded as a false negative.
- **CWE-78 (command injection)** — Polymorphic command builders (`helpers/Utils.executeCmd`) may strip or escape input before `Runtime.exec` runs; the snippet doesn't show the helper body.

Mitigations available today: the question YAMLs for these rules declare `additional_context: ["caller", "global"]` and `min_iterations: 2` so a context-aware run (CLI verify with a populated `output/context/`) can request the helper file. A follow-up could wire a minimal `_SnippetContextProvider` for benchmark mode that serves an allow-listed set of repo-root helpers (`BenchmarkRunner.properties`, `helpers/Utils.java`).

### Live progress

```
  ▶  secllmholmes × vulnhunterx  [228 entries]
  [secllmholmes × vulnhunterx]  47/228  TP:23 FP:18 NMD:4 ERR:2  $0.42  3.2 s/entry  ETA 9m42s
  ✓ secllmholmes × vulnhunterx  228/228  P=82.1% R=91.3% F1=86.5%  $1.84  12m15s
```

Use `--verbose` for one line per entry, `--quiet` for log lines only.

---

## Resuming Interrupted Runs

Every run creates a new timestamped directory and does **not** auto-resume. Pair `--run-dir` with `--resume` to recover:

```bash
# Start with a stable directory name
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run

# Resume after Ctrl+C or system kill
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run --resume

# Inspect status mid-run
grep -h '"status"' benchmarks/results/my_run/*_results.json

# Generate a report from partial or completed results
python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/my_run
```

### Resume semantics

| Checkpoint state             | `--resume` set | Behaviour                                             |
| ---------------------------- | -------------- | ----------------------------------------------------- |
| `completed`                  | yes            | Skip pair entirely                                    |
| `in_progress`                | yes            | Restore prior entries; continue from where it stopped |
| `completed` or `in_progress` | no             | Overwrite and restart the pair (logged as warning)    |
| missing                      | either         | Start fresh                                           |

Checkpointing is per-entry by default (`--checkpoint-every 1`). For cheap approaches you can amortize:

```bash
python benchmarks/scripts/run_benchmark.py \
    --approach raw-sast --checkpoint-every 50 --run-dir benchmarks/results/my_run
```

---

## Adding Datasets or Approaches

### New dataset

1. Create an adapter in `benchmarks/adapters/` implementing `load() -> list[GroundTruthEntry]`.
2. Add a setup branch to `benchmarks/scripts/setup_datasets.py`.
3. Add a loader branch to `_load_dataset()` in `benchmarks/scripts/run_benchmark.py`.
4. Add a fixture file at `benchmarks/fixtures/<name>_sample.json`.
5. Add unit tests in `tests/test_benchmark_adapters.py`.

### New approach

1. Subclass `BenchmarkApproach` in `benchmarks/approaches/`.
2. Implement `evaluate(entry: GroundTruthEntry) -> BenchmarkResult`.
3. Register it in `_build_approach()` in `run_benchmark.py`.
