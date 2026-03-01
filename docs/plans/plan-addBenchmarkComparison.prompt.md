## Plan: Benchmarking Framework for VulnHunterX

**TL;DR** — Add a standalone `benchmarks/` directory with scripts, datasets, and evaluation logic to compare VulnHunterX against three baselines (raw SAST, SecLLMHolmes-style single-shot, generic LLM prompt) on three ground-truth datasets (SecLLMHolmes scenarios, Juliet C/C++, CVEfixes real-world). Measure accuracy (precision/recall/F1), false-positive reduction rate, and cost/latency. Results are saved as JSON and rendered into a Markdown report table.

**Steps**

### Phase 1: Infrastructure (benchmarks module + ground-truth schema)

1. Create directory structure:
   ```
   benchmarks/
   ├── README.md              # How to run benchmarks, dataset setup, interpreting results
   ├── requirements.txt       # Extra deps (pandas, tabulate, matplotlib)
   ├── config/
   │   └── benchmark.yaml     # Dataset paths, LLM model list, iteration counts
   ├── datasets/              # Ground-truth data (git-ignored, downloaded by setup script)
   │   ├── secllmholmes/      # Cloned from github.com/ai4cloudops/SecLLMHolmes
   │   ├── juliet/            # Downloaded from NIST SARD
   │   └── cvefixes/          # CVEfixes SQLite DB + cloned vulnerable commits
   ├── scripts/
   │   ├── setup_datasets.py  # Download/clone all datasets
   │   ├── run_benchmark.py   # Main entry point: orchestrates all evaluations
   │   ├── run_secllmholmes.py
   │   ├── run_juliet.py
   │   ├── run_cvefixes.py
   │   └── generate_report.py # Aggregate results → Markdown + CSV tables
   ├── adapters/
   │   ├── __init__.py
   │   ├── ground_truth.py    # GroundTruthEntry dataclass, load/normalize across datasets
   │   ├── sarif_synth.py     # Synthesize SARIF Finding objects from non-SARIF datasets
   │   ├── secllmholmes_adapter.py  # Parse SecLLMHolmes 228 scenarios → GroundTruthEntry
   │   ├── juliet_adapter.py  # Parse Juliet test cases → GroundTruthEntry (from filename convention)
   │   ├── cvefixes_adapter.py # Query CVEfixes SQLite → GroundTruthEntry
   │   └── cwe_rule_map.py    # Bidirectional CWE ↔ CodeQL rule ID mapping
   ├── baselines/
   │   ├── __init__.py
   │   ├── raw_sast.py        # Baseline 1: raw CodeQL/Semgrep output (no LLM)
   │   ├── single_shot_llm.py # Baseline 2: SecLLMHolmes-style single-shot prompt
   │   └── generic_prompt.py  # Baseline 3: generic LLM prompt without guided questions
   ├── metrics/
   │   ├── __init__.py
   │   └── evaluator.py       # Compute precision, recall, F1, FP reduction rate, cost, latency
   └── results/               # Output directory for benchmark runs (git-ignored)
   ```

2. Define a `GroundTruthEntry` dataclass in `benchmarks/adapters/ground_truth.py` with fields: `id`, `source_dataset`, `cwe_id`, `rule_id`, `file_path`, `function_name`, `start_line`, `lang`, `label` (TP/FP/BENIGN), `code_snippet`, `metadata` (dict). This is the common schema all dataset adapters produce.

3. Build CWE ↔ CodeQL rule ID mapping table in `benchmarks/adapters/cwe_rule_map.py`, sourced from the existing mappings in `docs/codeql_cpp_security.md`, `docs/codeql_python_security.md`, and `docs/codeql_javascript_security.md`. Cover the overlap with Juliet CWEs (~30 high-priority CWEs like CWE-416, CWE-476, CWE-119, CWE-190, CWE-78, CWE-89, CWE-787, CWE-22, CWE-125).

### Phase 2: Dataset Adapters

4. **SecLLMHolmes adapter** (`benchmarks/adapters/secllmholmes_adapter.py`): Clone `github.com/ai4cloudops/SecLLMHolmes`, parse their `datasets/` directory (organized by CWE → complexity level), extract each scenario's code + ground-truth label. Map their 8 CWE classes to CodeQL rule IDs. Produce `GroundTruthEntry` objects. This is the smallest dataset (~228 scenarios) and the most direct competitor comparison.

5. **Juliet adapter** (`benchmarks/adapters/juliet_adapter.py`): Download Juliet C/C++ 1.3.1 from NIST SARD. The adapter should:
   - Either (a) run CodeQL on the Juliet source to produce real SARIF, *or* (b) synthesize `Finding` objects from the file naming convention (`_bad` = vulnerable, `_good` = safe).
   - Option (a) is preferred for testing the full pipeline; option (b) for quick/offline benchmarking.
   - Ground truth: if a CodeQL finding points to a `bad()` function → TP; if it points to a `good()` function → FP; findings CodeQL missed entirely → FN.
   - Focus on ~15 CWEs where CodeQL rules exist (CWE-416, CWE-476, CWE-190, CWE-119, CWE-787, CWE-78, CWE-22, CWE-125, CWE-134, CWE-401, etc.).

6. **CVEfixes adapter** (`benchmarks/adapters/cvefixes_adapter.py`): Download the CVEfixes SQLite database. Query for entries matching target languages (C, C++, Python, JavaScript, PHP) and CWEs overlapping with CodeQL rules. For each CVE:
   - Clone the repo at the vulnerable commit.
   - Run CodeQL to produce SARIF.
   - Cross-reference SARIF findings with CVEfixes ground truth (file + function + CWE).
   - **Curate a subset** (~50-100 CVEs across languages) to keep benchmark runtime manageable.
   - This tests the *full realistic pipeline*: real code → real SAST → LLM verification.

7. **Synthetic SARIF generator** (`benchmarks/adapters/sarif_synth.py`): For datasets that don't naturally produce SARIF (SecLLMHolmes, PrimeVul), create synthetic `Finding` objects by populating `rule_id` (from CWE mapping), `message`, `file`, `start_line`, `lang`, etc. This feeds directly into `VerificationEngine._verify_single_finding()`.

### Phase 3: Baseline Implementations

8. **Raw SAST baseline** (`benchmarks/baselines/raw_sast.py`): Treat every SARIF finding as a TP. No LLM involved. This measures CodeQL/Semgrep's native precision and establishes the upper bound on recall. The FP reduction rate of LLM-based approaches is measured *relative* to this baseline.

9. **Single-shot LLM baseline** (`benchmarks/baselines/single_shot_llm.py`): Implement SecLLMHolmes-style evaluation — send a single prompt with the code snippet + vulnerability question to the LLM, parse the yes/no/unsure response. No multi-turn, no guided questions, no dynamic context expansion. Reuse VulnHunterX's `LLMClient` but with `max_iterations=1` and a generic prompt template (no rule-specific questions).

10. **Generic prompt baseline** (`benchmarks/baselines/generic_prompt.py`): Use VulnHunterX's multi-turn engine but replace `QuestionsLoader` with a single generic question ("Is this code vulnerable?"). This isolates the contribution of rule-specific guided questions vs. the multi-turn mechanism.

### Phase 4: Metrics & Evaluation Engine

11. **Metrics module** (`benchmarks/metrics/evaluator.py`): Compute per-dataset and per-CWE:
    - **Accuracy metrics**: Precision, Recall, F1 score (binary: TP vs FP/Benign)
    - **FP reduction rate**: `(SAST_FPs - Tool_FPs) / SAST_FPs × 100%` — how many raw SAST false positives each approach eliminates
    - **TP preservation rate**: `Tool_TPs / SAST_TPs × 100%` — ensure LLM doesn't suppress real bugs
    - **Cost metrics**: total LLM API tokens used, estimated USD cost (from LiteLLM response metadata), tokens-per-finding
    - **Latency metrics**: wall-clock time per finding (mean, median, p95), total benchmark time
    - Handle `NEEDS_MORE_DATA` verdicts: count separately, optionally treat as FP or exclude
    - Output format: JSON with per-finding results + aggregate summary

12. Map `VerdictType` to binary labels for metrics: `TRUE_POSITIVE` → predicted positive, `FALSE_POSITIVE` → predicted negative, `NEEDS_MORE_DATA` → configurable (exclude or count as FP), `ERROR` → exclude.

### Phase 5: Orchestration & Reporting

13. **Main runner** (`benchmarks/scripts/run_benchmark.py`): Orchestrate the full benchmark:
    - Accept CLI args: `--dataset` (secllmholmes/juliet/cvefixes/all), `--baseline` (raw-sast/single-shot/generic/all), `--model` (gpt-4o/claude-sonnet/etc.), `--limit` (cap findings per dataset)
    - For each dataset × approach combination: load ground truth → run the approach → collect verdicts → compute metrics
    - Save raw results to `benchmarks/results/<timestamp>/`
    - Support resumption: skip already-completed (dataset, approach) pairs

14. **Report generator** (`benchmarks/scripts/generate_report.py`): Read results JSON files, produce:
    - Markdown comparison table (rows = approaches, columns = metrics)
    - Per-CWE breakdown table
    - Cost/latency comparison
    - Optionally: matplotlib charts for precision-recall curves and per-CWE heatmaps
    - Write to `benchmarks/results/<timestamp>/REPORT.md`

15. **Per-dataset scripts** (`benchmarks/scripts/run_secllmholmes.py`, etc.): Convenience wrappers that run a single dataset benchmark with sensible defaults. Useful for quick iteration.

### Phase 6: Documentation & Integration

16. Write `benchmarks/README.md` documenting:
    - Prerequisites (CodeQL, API keys, disk space for datasets)
    - Setup: `python benchmarks/scripts/setup_datasets.py` (downloads ~2 GB)
    - Quick run: `python benchmarks/scripts/run_benchmark.py --dataset secllmholmes --limit 50`
    - Full run: `python benchmarks/scripts/run_benchmark.py --dataset all --baseline all`
    - Interpreting results
    - Adding new datasets/baselines

17. Add `benchmarks/results/` and `benchmarks/datasets/` to `.gitignore` to avoid committing large data or API-cost results.

18. Add a `benchmark` optional dependency group to `pyproject.toml` with `pandas`, `tabulate`, `matplotlib` (optional for charts).

### Research Papers & References

The following papers and resources informed the benchmark design, dataset selection, and competitor methodology:

#### Core Methodology

- **Vulnhalla** — *Picking the True Vulnerabilities from the CodeQL Haystack* (CyberArk, 2024)
  https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack
  The foundational methodology for VulnHunterX: rule-specific guided questions + multi-turn LLM conversation to triage CodeQL findings. Demonstrated significant FP reduction on real-world C/C++ repos.

#### Competitor / Evaluation Frameworks

- **SecLLMHolmes** — *LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?)* (IEEE S&P 2024)
  Paper: https://arxiv.org/abs/2312.12575
  Code: https://github.com/ai4cloudops/SecLLMHolmes
  Evaluates LLMs across 228 hand-crafted C/C++ and Python scenarios, 8 CWE classes, and 17 prompting strategies. Key finding: LLM reasoning is often unfaithful — renaming variables changes 26% of GPT-4 answers. Uses **single-shot prompting** (no multi-turn), making it a direct contrast to VulnHunterX's approach. Their dataset and evaluation dimensions (identification, classification, location, robustness) form the basis of our primary benchmark.

- **IRIS** — *LLM-Aided Static Analysis for Detecting Security Vulnerabilities* (arXiv, 2024)
  Paper: https://arxiv.org/abs/2405.17238
  Enhances SAST with LLM-generated specifications rather than post-hoc triage. Uses LLMs to synthesize function summaries that help static analyzers reason across procedure boundaries. Different philosophy from VulnHunterX (augment SAST vs. filter SAST output).

- **LLift** — *A Framework for LLM-Facilitated Static Analysis* (arXiv, 2023)
  Paper: https://arxiv.org/abs/2308.13416
  Uses LLMs to infer missing program facts (e.g., pointer aliasing, integer ranges) that static analyzers cannot determine, then feeds these facts back into the analyzer. Evaluated on Linux kernel bugs. Complementary approach to VulnHunterX's post-analysis verification.

- **GPTScan** — *Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis* (ICSE 2024)
  Paper: https://arxiv.org/abs/2308.03314
  Combines GPT with static analysis for smart contract vulnerability detection. Although domain-specific (Solidity), it pioneered the SAST+LLM combination pattern. Useful comparison point for the single-shot LLM prompting approach.

#### Benchmark Datasets

- **NIST SARD / Juliet Test Suite** — *Software Assurance Reference Dataset* (NIST)
  https://samate.nist.gov/SARD/test-suites
  Industry-standard synthetic test suite: 64,099 C/C++ test cases across ~180 CWEs. Each test case has `bad()` (vulnerable) and `good()` (safe) functions with deterministic ground truth from naming conventions. Latest: Juliet C/C++ 1.3.1 (Aug 2022).

- **CVEfixes** — *Automatically Collected Vulnerabilities and Their Fixes from Open-Source Software* (PROMISE 2021)
  Paper: https://arxiv.org/abs/2107.08760
  Data: https://zenodo.org/records/7029359
  Code: https://github.com/secureIT-project/CVEfixes
  SQLite database with 12,107 vulnerability-fixing commits across 4,249 projects. Multi-language coverage. Includes CVE-to-commit-to-file-to-function mappings. v1.0.8 covers CVEs through July 2024.

- **PrimeVul** — *Vulnerability Detection with Code Language Models: How Far Are We?* (ICSE 2025)
  Paper: https://arxiv.org/abs/2403.18624
  Code: https://github.com/DLVulDet/PrimeVul
  High-quality C/C++ function-level vulnerability dataset (~7K vulnerable + ~229K benign functions, 140+ CWE types). Demonstrated that Big-Vul's label noise inflates reported model performance (68% F1 on Big-Vul drops to 3% on PrimeVul). Chronological splits minimize data contamination. Deferred to Phase 2 due to SARIF mapping complexity.

- **Big-Vul** — *A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries* (MSR 2020)
  Code: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
  21-feature CSV with CVE-to-function mappings for C/C++ code (2002–2019). Widely used but **known label-noise issues** — PrimeVul paper showed models trained on Big-Vul fail on cleaner data. Included here for reference only; CVEfixes is preferred.

#### LLM-for-Security Surveys

- **Large Language Models for Software Engineering: A Systematic Literature Review** (ACM TOSEM 2024)
  Paper: https://arxiv.org/abs/2308.10620
  Comprehensive survey covering LLM applications in vulnerability detection, code repair, and program analysis. Useful for positioning VulnHunterX within the broader research landscape.

- **Software Vulnerability Detection using Large Language Models** (arXiv, 2024)
  Paper: https://arxiv.org/abs/2401.17010
  Reviews approaches for LLM-based vulnerability detection including fine-tuning vs. prompting, single-shot vs. multi-turn, and integration with static analysis tools. Benchmarks on Big-Vul and Devign datasets.

### Verification

- **Unit tests**: Test adapters with small fixture files (5-10 entries each) — add to `tests/test_benchmark_adapters.py`
- **Smoke test**: `python benchmarks/scripts/run_benchmark.py --dataset secllmholmes --limit 5 --baseline raw-sast` should complete in <10 seconds (no LLM calls)
- **Integration test**: `python benchmarks/scripts/run_benchmark.py --dataset secllmholmes --limit 10 --baseline all --model gpt-4o-mini` — verify all 4 approaches produce valid JSON results and the report generates correctly
- **Validate metrics**: On Juliet, raw SAST baseline should have recall=1.0 (by definition) and known-low precision; VulnHunterX should improve precision while preserving most recall

### Decisions

- **Standalone scripts** (not a CLI command): benchmarks live in `benchmarks/` as standalone Python scripts, separate from the `vuln-hunter-x` CLI, per your preference
- **SecLLMHolmes as primary competitor**: Its 228 hand-crafted scenarios with known ground truth provide the most direct comparison — VulnHunterX's multi-turn guided approach vs single-shot prompting on identical code
- **CVEfixes over Big-Vul**: CVEfixes is better maintained, multi-language, and has richer metadata (commit-level); Big-Vul has known label-noise issues documented by the PrimeVul paper
- **PrimeVul as stretch goal**: It's function-level C/C++ only and requires either synthetic SARIF or full CodeQL runs on originating repos — high effort. Defer to Phase 2 of benchmarking
- **`NEEDS_MORE_DATA` handling**: Default to excluding from precision/recall calculation (with a separate "inconclusive rate" metric), configurable in `benchmark.yaml`
