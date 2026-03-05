# VulnHunterX Benchmarks

Standalone benchmark framework comparing VulnHunterX against three baselines on three ground-truth datasets. No CLI installation required — run directly as Python scripts.

---

## Approaches Compared

| Approach            | Description                                                                     |
| ------------------- | ------------------------------------------------------------------------------- |
| `raw-sast`          | Every SAST finding = TP, no LLM. Establishes upper-bound recall.                |
| `single-shot`       | Single LLM call, generic questions, no multi-turn (SecLLMHolmes-style).         |
| `generic-questions` | Multi-turn LLM with only `default_questions.yaml` (no rule-specific questions). |
| `vulnhunterx`       | Full system: rule-specific guided questions + multi-turn context expansion.     |

---

## Datasets

| Dataset                | Size           | Language       | Ground Truth                                          |
| ---------------------- | -------------- | -------------- | ----------------------------------------------------- |
| **SecLLMHolmes**       | ~228 scenarios | C/C++, Python  | Handcrafted bad/good code pairs, 8 CWE classes        |
| **Juliet C/C++ 1.3.1** | 64K test cases | C, C++         | NIST synthetic bad()/good() function pairs, ~180 CWEs |
| **CVEfixes**           | ~12K commits   | Multi-language | Real CVE-fixing commits mapped to functions           |

---

## Prerequisites

- Python 3.12+ with VulnHunterX installed (`pip install -e .`)
- For LLM approaches: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or Ollama running locally
- For chart generation: `pip install -e ".[benchmark]"`
- ~14 GB disk space for full datasets (SecLLMHolmes + Juliet + CVEfixes)
- CodeQL CLI (optional; only needed for Juliet "full" mode)

---

## Quick Start

### 1. Smoke test — no LLM, no dataset download

```bash
# Uses fixture files (10 hand-curated entries per dataset)
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach raw-sast --limit 10
# Completes in <5 seconds
```

### 2. Dry-run — mock LLM, test all code paths

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all --limit 20 --dry-run
```

### 3. Download datasets

```bash
# List available datasets
python benchmarks/scripts/setup_datasets.py --list

# Download a single dataset (~50 MB)
python benchmarks/scripts/setup_datasets.py --dataset secllmholmes

# Download all datasets (~14 GB total)
python benchmarks/scripts/setup_datasets.py --dataset all
```

### 4. Real benchmark run (small)

```bash
# Single-shot baseline only, 50 entries, cheapest model
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all \
    --model gpt-4o-mini --limit 50
```

### 5. Generate report

```bash
python benchmarks/scripts/generate_report.py \
    --run-dir benchmarks/results/<timestamp>

# With charts (requires matplotlib)
python benchmarks/scripts/generate_report.py \
    --run-dir benchmarks/results/<timestamp> --charts
```

### 6. Full benchmark

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o
```

### 7. Iteration sweep (measure multi-turn contribution)

```bash
# Runs VulnHunterX at max_iterations = 1, 2, 3
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach vulnhunterx \
    --model gpt-4o-mini --iteration-sweep
```

### 8. Resumable run — survive Ctrl+C

```bash
# Start a run with a named directory
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run

# Interrupted? Resume exactly where it stopped:
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run --resume
```

---

## CLI Reference

### `run_benchmark.py`

```
--dataset          secllmholmes | juliet | cvefixes | all  (default: secllmholmes)
--approach         raw-sast | single-shot | generic-questions | vulnhunterx | all
--model            LLM model name  (default: gpt-4o)
--provider         openai | anthropic | ollama  (default: openai)
--limit            Max entries per dataset, 0=all  (default: 0)
--max-iterations   Multi-turn rounds for vulnhunterx/generic  (default: 3)
--nmd-handling     exclude | fp  (default: exclude)
--dry-run          Mock LLM responses — no API cost
--resume           Skip completed pairs; continue in-progress pairs from last checkpoint
--run-dir PATH     Explicit output directory (use with --resume for recovery)
--run-id ID        Timestamp alias for --run-dir (e.g. 20260305_113225)
--checkpoint-every N  Save incremental checkpoint every N entries (default: 1)
--verbose / -v     Print a detailed line per entry during the run
--quiet            Suppress progress display; emit log lines only
--iteration-sweep  Run vulnhunterx at iterations=1,2,3
```

### `setup_datasets.py`

```
--dataset  secllmholmes | juliet | cvefixes | all  (default: all)
--list     List available datasets and exit
```

### `generate_report.py`

```
--run-dir  Path to benchmark run directory  (required)
--charts   Generate matplotlib precision/recall charts
```

---

## Metrics Explained

| Metric                     | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| **Precision**              | Of findings predicted TP, how many are actually vulnerable?        |
| **Recall**                 | Of all truly vulnerable findings, how many did we catch?           |
| **F1**                     | Harmonic mean of precision and recall                              |
| **FP Reduction Rate**      | (raw-SAST FPs − approach FPs) / raw-SAST FPs                       |
| **TP Preservation Rate**   | approach TPs / raw-SAST TPs (must stay high)                       |
| **NMD Rate**               | Fraction returning "Needs More Data" (excluded from P/R/F1)        |
| **Confidence Calibration** | Within each confidence bucket, what % of predictions were correct? |
| **Tokens/Finding**         | Average LLM tokens consumed per finding                            |
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
└── precision_recall.png                # Chart (if --charts used)
```

---

## Interpreting Results

**Good result for VulnHunterX:**
- `raw-sast`: recall=100% (by definition), precision=~40% (typical SAST noise)
- `vulnhunterx`: precision improves to >80%, recall stays >85%
- FP reduction rate: >50% (eliminates more than half of raw SAST false positives)
- Confidence calibration: High confidence predictions are >90% accurate

**Warning signs:**
- TP preservation rate <80% → VulnHunterX is suppressing real bugs
- NMD rate >30% → LLM is not getting enough context to make decisions
- Calibration flat across High/Medium/Low → confidence scores are meaningless

---

## Resuming Interrupted Runs

By default every run creates a new timestamped directory and does **not** auto-resume.
To recover from an interruption, use `--run-dir` with `--resume`:

```bash
# 1. Start with an explicit, stable directory name
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run

# 2. Interrupted by Ctrl+C or system kill? Resume:
python benchmarks/scripts/run_benchmark.py \
    --dataset all --approach all --model gpt-4o \
    --run-dir benchmarks/results/my_run --resume

# 3. Inspect what has been completed vs in-progress:
grep -h '"status"' benchmarks/results/my_run/*_results.json

# 4. Generate report from partial or completed results:
python benchmarks/scripts/generate_report.py \
    --run-dir benchmarks/results/my_run
```

### Resume semantics

| Checkpoint state             | `--resume` set | Behaviour                                             |
| ---------------------------- | -------------- | ----------------------------------------------------- |
| `completed`                  | yes            | Skip pair entirely                                    |
| `in_progress`                | yes            | Restore prior entries; continue from where it stopped |
| `completed` or `in_progress` | no             | Overwrite and restart the pair (logged as warning)    |
| Missing                      | either         | Start fresh                                           |

Progress is checkpointed every entry by default (`--checkpoint-every 1`).
You can increase this for faster approaches:

```bash
python benchmarks/scripts/run_benchmark.py \
    --approach raw-sast --checkpoint-every 50 --run-dir benchmarks/results/my_run
```

### CLI progress display

During a run, each pair shows a live progress line on stderr:

```
  ▶  secllmholmes × vulnhunterx  [228 entries]
  [secllmholmes × vulnhunterx]  47/228  TP:23 FP:18 NMD:4 ERR:2  $0.42  3.2s/entry  ETA 9m42s
  ✓ secllmholmes × vulnhunterx  228/228  P=82.1% R=91.3% F1=86.5%  $1.84  12m15s
```

Use `--verbose` (or `-v`) for a detailed line per entry:

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach vulnhunterx --limit 20 --verbose --dry-run
```

Use `--quiet` to suppress progress display and get plain log lines only
(useful when piping output to a file).

---

## Adding New Datasets

1. Create an adapter in `benchmarks/adapters/` implementing `load() -> list[GroundTruthEntry]`
2. Add dataset setup to `benchmarks/scripts/setup_datasets.py`
3. Add loader branch to `_load_dataset()` in `benchmarks/scripts/run_benchmark.py`
4. Add fixture file to `benchmarks/fixtures/<name>_sample.json`
5. Add unit tests in `tests/test_benchmark_adapters.py`

## Adding New Approaches

1. Create a class in `benchmarks/approaches/` extending `BenchmarkApproach`
2. Implement `evaluate(entry: GroundTruthEntry) -> BenchmarkResult`
3. Register in `_build_approach()` in `run_benchmark.py`
