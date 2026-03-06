# Implementation Plan: VulnHunterX Benchmark Improvements

## Context

The benchmark report (20260305_191902) reveals 5 concrete problems:
1. **42.4% NMD rate** masking real coverage issues (TP preservation only 68.8%)
2. **Token/cost tracking broken** (all zeros despite 3.5h of API calls)
3. **Effective recall absent** from report (Recall=100% is misleading when NMDs excluded)
4. **Code slicing not implemented** (LLM receives full function bodies; LLM4FPM shows slices improve accuracy)
5. **Benchmark coverage limited** (only secllmholmes; Juliet adapter exists but untested; no real-world dataset)

### Root Cause of High NMD Rate

`VulnHunterXApproach` passes `context_provider=None`. In `client.py:182`, the condition
`not context_provider` is **always True**, so the loop exits after 1 iteration even when LLM
returns NMD. `max_iterations` is irrelevant. The fix is a "force decision" second turn.

### Research-Backed Improvements (from literature review)

- **Self-consistency with confidence (CISC, ACL 2025)**: Instead of a single forced re-prompt,
  sample N responses and use majority vote. Achieves same accuracy as standard self-consistency
  with 46% fewer samples. We add this as an optional parameter for the force-decision step.
- **LLMxCPG (USENIX Security 2025)**: Code Property Graph-guided slicing reduces code by
  68-91% while preserving vulnerability context. Our regex-based `SlicedContextExtractor` is
  a pragmatic Phase 1; CPG slicing is a future enhancement.
- **D2A dataset quality issues**: D2A has consistency=0.531 and avg 57 duplicates per function
  (ICSE 2023 data quality study). **DiverseVul** (RAID 2023) is a better choice -- 18,945
  vulnerable + 330,492 non-vulnerable functions, 150 CWEs, real CVE-backed labels, public
  GitHub repo (wagner-group/diversevul).

Sources:
- CISC: https://aclanthology.org/2025.findings-acl.1030.pdf
- LLMxCPG: https://arxiv.org/abs/2507.16585
- DiverseVul: https://github.com/wagner-group/diversevul
- D2A quality: https://rolandcroft.github.io/assets/publications/ICSE_23.pdf
- ZeroFalse: https://arxiv.org/abs/2510.02534
- LLM4FPM: https://arxiv.org/abs/2411.03079
- Sifting the Noise: https://arxiv.org/abs/2601.22952

---

## Feature A: Force Decision on NMD + max_iterations=3

### A1. Add `force_decision` flag to `LLMClient.analyze()`

**File**: `src/vuln_hunter_x/llm/client.py`

- Add parameter `force_decision: bool = True` to `analyze()` at line 55
- When the early-exit condition at line 182 fires with `verdict == "Needs More Data"`, check
  `force_decision`. If True, do **one additional forced turn** before returning.
- Forced turn prompt text (hardcoded constant):
  ```
  "This is your final analysis attempt. Based on the code provided, you MUST choose
  True Positive or False Positive. Low confidence is acceptable. Needs More Data is
  NOT an acceptable final response. Give your best judgment."
  ```
- Append forced turn as user message, call LLM once more, parse response
- If the forced response is still NMD, convert it to `False Positive` with `Low` confidence
  (conservative: when uncertain, prefer not alarming; acceptable to override via config)
- Also apply force_decision at the max-iterations exit path (line 255)
- New helper: `_build_force_decision_prompt() -> str` (private method)
- **Optional self-consistency mode** (`force_decision_samples: int = 1`):
  - When `> 1`, run N parallel LLM calls (temperature=0.7) with the force-decision prompt,
    take majority vote across TP/FP responses for higher reliability
  - Default `1` (single forced re-prompt) for cost efficiency
  - Majority vote logic: count TP vs FP across N responses; ties -> FP (conservative)
  - This follows the CISC approach (ACL 2025) achieving same accuracy with fewer samples

### A2. Soften system prompt

**File**: `config/prompts/system_prompt.yaml`

- Remove or soften the line "prefer Needs More Data over guessing"
- Replace with: "Use Needs More Data only when specific additional context (caller, struct,
  global) would genuinely change your verdict. Do not use it to avoid making a judgment."

### A3. Propagate `force_decision` through Config and VerificationEngine

**File**: `src/vuln_hunter_x/core/config.py`

- Add `force_decision: bool = True` field (default True)
- Read from config dict in `from_dict()` and `from_yaml()`

**File**: `src/vuln_hunter_x/verification/engine.py`

- Pass `config.force_decision` through to `LLMClient.analyze()` call

### A4. Pass `force_decision` in benchmark approach

**File**: `benchmarks/approaches/vulnhunterx.py`

- Add `force_decision: bool = True` param to `__init__` (default True)
- Pass to `Config.from_dict()` as `"force_decision": self._force_decision`

**File**: `benchmarks/scripts/run_benchmark.py`

- Add `--force-decision / --no-force-decision` CLI flag (default: force-decision enabled)
- Pass to `_build_approach()` -> `VulnHunterXApproach`

### A5. Ensure max_iterations=3 used in benchmark

The `--max-iterations` CLI arg already defaults to 3. No code change needed.
Confirm `config/benchmark.yaml` has `max_iterations: 3`.

---

## Feature B: Token & Cost Tracking Fix

### B1. Add `tokens_used` and `cost_usd` to `Verdict`

**File**: `src/vuln_hunter_x/core/types.py`

- Add two fields to `Verdict` dataclass (after `iterations: int = 1`):
  ```python
  tokens_used: int = 0
  cost_usd: float = 0.0
  ```
- Add to `to_dict()` output

### B2. Read token usage from LiteLLM response

**File**: `src/vuln_hunter_x/llm/client.py`

- After `response = litellm.completion(...)` at line 152, read token count:
  ```python
  _tokens = getattr(getattr(response, "usage", None), "total_tokens", 0) or 0
  ```
- Accumulate tokens across iterations in `total_tokens_used: int = 0` local variable
- For cost, use LiteLLM's built-in: `litellm.completion_cost(completion_response=response)`,
  wrapped in try/except (returns 0.0 on unknown models)
- Accumulate cost in `total_cost_usd: float = 0.0` local variable
- Pass `tokens_used=total_tokens_used, cost_usd=total_cost_usd` into each returned `Verdict`

### B3. Propagate tokens through benchmark results

**File**: `benchmarks/approaches/vulnhunterx.py` (and `single_shot.py`, `generic_questions.py`)

- After `v = result.verdicts[0]`, read `v.tokens_used` and `v.cost_usd`
- Pass them to `BenchmarkResult(... tokens_used=v.tokens_used, cost_usd=v.cost_usd)`

---

## Feature C: Effective Recall Metric

### C1. Track NMD-TP count in evaluator

**File**: `benchmarks/metrics/evaluator.py`

- Add `nmd_tp_count: int = 0` field to `ApproachMetrics` dataclass (line ~82)
- In `evaluate()`, where NMD entries are handled (line ~264): check `gt_label`:
  ```python
  if pred == PRED_NMD:
      metrics.pred_nmd += 1
      if r.entry.label == LABEL_TP:
          metrics.nmd_tp_count += 1   # new
      ...
  ```
- Add `effective_recall` property to `ApproachMetrics`:
  ```python
  @property
  def effective_recall(self) -> float | None:
      denom = self.tp_correct + self.tp_missed + self.nmd_tp_count
      return self.tp_correct / denom if denom else None
  ```
- Add `"effective_recall": _fmt(self.effective_recall)` to `summary_dict()`

### C2. Add effective_recall column to REPORT.md

**File**: `benchmarks/scripts/generate_report.py`

- Add `"Eff. Recall"` to `headers` in `_main_table()` (line 58)
- Add `_pct(s.get("effective_recall"))` to the corresponding row (line 66 block)
- Update the footnote under the table to explain:
  `Eff. Recall = TPs confirmed / (TPs confirmed + TPs missed + NMDs that were TPs)`

---

## Feature D: Code Slicing Context Extractor

> **Background**: LLM4FPM (2024) shows precise code slices dramatically improve FP filtering
> accuracy. LLMxCPG (USENIX Security 2025) shows CPG-based slicing reduces code 68-91% while
> preserving vulnerability context. Our approach: Phase 1 uses SARIF `codeFlows` + regex-based
> variable tracking (pragmatic, no new dependencies). Phase 2 (future) would integrate CPG
> slicing via CodeQL's data flow libraries.

### D1. Parse SARIF `codeFlows` into `Finding`

**File**: `src/vuln_hunter_x/core/types.py`

- Add `dataflow_path: list[str] = field(default_factory=list)` to `Finding` dataclass
- Add to `to_dict()` / update `Finding.location` if needed

**File**: `src/vuln_hunter_x/sarif/parser.py`

- In `parse_findings()`, after extracting rule_id/message/locations, also extract `codeFlows`:
  ```python
  dataflow_path = _extract_dataflow_path(result.get("codeFlows", []))
  ```
- New helper `_extract_dataflow_path(code_flows: list) -> list[str]`:
  - Iterates `codeFlows[0].threadFlows[0].locations`
  - Each location has `physicalLocation.region.startLine` and `message.text`
  - Builds a list like `["line 12: buf = malloc(100)", "line 45: strcpy(buf, src)"]`
  - Returns empty list if no codeFlows
- Pass `dataflow_path=dataflow_path` to `Finding(...)`

### D2. Create `SlicedContextExtractor`

**File**: `src/vuln_hunter_x/context/extractor.py`

Add `SlicedContextExtractor` class next to the existing `ContextExtractor`:

- Constructor takes `code: str`, `target_line: int`, `message: str`, `window: int = 5`
- `_extract_key_variable(message: str) -> str | None`: regex to pull variable/symbol name
  from SARIF messages like "Use of potentially uninitialized variable 'buf'" -> `"buf"`
- `extract(finding: Finding) -> CodeContext`:
  - Get variable name from finding.message
  - If dataflow_path is available in finding, return those lines directly as slice
  - Otherwise: scan the code lines for lines referencing the variable + `+/-window` lines
    around the flagged line; deduplicate and sort line numbers
  - Return the slice as `CodeContext`

**File**: `benchmarks/approaches/base.py`

- Update `_SnippetContextExtractor` to optionally use slicing:
  - Add `use_slicing: bool = False` param to `__init__`
  - When `use_slicing=True`, instantiate `SlicedContextExtractor` internally and delegate

**File**: `benchmarks/approaches/vulnhunterx.py`

- Add `use_slicing: bool = False` param (default False for backward compatibility)
- Pass to `_SnippetContextExtractor(... use_slicing=use_slicing)`

**File**: `benchmarks/scripts/run_benchmark.py`

- Add `--sliced-context` flag; pass to `_build_approach()` for VulnHunterX approach

### D3. Include dataflow_path in LLM prompt

**File**: `src/vuln_hunter_x/llm/prompts.py`

- In `build_user_prompt()`, if `finding.dataflow_path` is non-empty, add a section:
  ```
  ## Dataflow Path (from static analysis)
  {chr(10).join(finding.dataflow_path)}
  ```
  Insert this between the code context and the guided questions.

---

## Feature E: Juliet Dataset (Enable & Verify)

### E1. Download Juliet if not present

**File**: `benchmarks/scripts/setup_datasets.py` (existing script)

- Verify Juliet download logic exists. If it downloads via `setup_datasets.py --dataset juliet`,
  ensure it works and the path matches `benchmarks/datasets/juliet/`.

### E2. Add Juliet fixture file

**File**: `benchmarks/fixtures/juliet_sample.json`

- Verify this exists and has the correct format (agent confirmed it exists).
- If empty, populate with ~10 entries from CWE-416 (UAF) and CWE-787 (OOB).

### E3. Run smoke test

After download, verify: `python benchmarks/scripts/run_benchmark.py --dataset juliet --approach raw-sast --limit 20`

---

## Feature F: DiverseVul Dataset Adapter (replaces D2A)

> **Why DiverseVul instead of D2A**: D2A has poor data quality (consistency=0.531, avg 57
> duplicates/function per ICSE 2023 study). DiverseVul (RAID 2023) is higher quality:
> 18,945 vulnerable + 330,492 non-vulnerable C/C++ functions, 150 CWEs, real CVE-backed
> labels. Public repo: github.com/wagner-group/diversevul.

### F1. Create DiverseVul adapter

**File**: `benchmarks/adapters/diversevul_adapter.py` (new file)

DiverseVul format: JSON lines with fields `func`, `target` (1=vuln, 0=safe), `cwe`,
`project`, `commit_id`.

```python
class DiverseVulAdapter:
    """Adapter for the DiverseVul dataset (RAID 2023).

    Source: https://github.com/wagner-group/diversevul
    Format: JSON lines -- {func, target, cwe, project, commit_id}
    """

    def __init__(self, dataset_path: Path): ...

    def load(self, limit: int = 0, cwes: list[str] | None = None) -> list[GroundTruthEntry]:
        # Read diversevul_20230702.json (JSON lines)
        # Map target: 1 -> "TP", 0 -> "FP"
        # Map cwe field to cwe_id (format: "CWE-XXX")
        # Optional cwes filter to select specific CWEs matching our benchmark scope
        # Generate ID: "dvul_" + md5(func)[:12]
        # Cap code_snippet at 8000 chars (same as JulietAdapter)
        # Default lang = "c" (dataset is C/C++ only)
        # Deduplicate by func hash (DiverseVul already deduplicated, but be safe)
```

### F2. Add DiverseVul download to setup script

**File**: `benchmarks/scripts/setup_datasets.py`

- Clone `https://github.com/wagner-group/diversevul` to `benchmarks/datasets/diversevul/`
- Or download `diversevul_20230702.json` directly (smaller footprint)
- Store in `benchmarks/datasets/diversevul/`

### F3. Register DiverseVul in runner

**File**: `benchmarks/scripts/run_benchmark.py`

- Add `"diversevul"` to `--dataset` choices (line 378)
- Add branch in `_load_dataset()` for `name == "diversevul"` (same pattern as juliet/cvefixes)
- Add DiverseVul to `"all"` datasets list (line 455)

### F4. Add DiverseVul fixture

**File**: `benchmarks/fixtures/diversevul_sample.json`

- 10-entry sample of TP + FP entries in `GroundTruthEntry` format
- Include entries from CWE-787, CWE-416, CWE-79 to match our existing CWE coverage

---

## Verification Plan

After implementation, run in order:

```bash
# 1. Unit tests (should all pass before and after)
.venv/bin/python -m pytest tests/ -v

# 2. Smoke test: force_decision effect on NMD rate
python benchmarks/scripts/run_benchmark.py \
  --dataset secllmholmes --approach vulnhunterx \
  --limit 20 --dry-run
# Verify: no NMD in dry-run (deterministic mock)

# 3. Real test: token tracking
python benchmarks/scripts/run_benchmark.py \
  --dataset secllmholmes --approach vulnhunterx \
  --limit 5
# Verify: tokens_used > 0 in results JSON

# 4. Juliet smoke test
python benchmarks/scripts/run_benchmark.py \
  --dataset juliet --approach raw-sast --limit 20
# Verify: entries loaded, precision/recall computed correctly

# 5. DiverseVul smoke test
python benchmarks/scripts/run_benchmark.py \
  --dataset diversevul --approach raw-sast --limit 20
# Verify: entries loaded, correct label distribution

# 6. Report with effective_recall
python benchmarks/scripts/generate_report.py \
  --run-dir benchmarks/results/<latest>
# Verify: "Eff. Recall" column present in REPORT.md
#         effective_recall < recall (shows NMD impact)

# 7. Code slicing integration test
python benchmarks/scripts/run_benchmark.py \
  --dataset secllmholmes --approach vulnhunterx \
  --limit 5 --sliced-context
# Verify: prompt sent to LLM contains sliced code (check log output)

# 8. Full force_decision benchmark (compare NMD rates)
python benchmarks/scripts/run_benchmark.py \
  --dataset secllmholmes --approach vulnhunterx \
  --limit 50
# Compare: NMD rate should drop from 42.4% to <15%
```

---

## Implementation Order

| # | Task | Files Changed | Risk |
|---|------|--------------|------|
| 1 | Token/Cost tracking (B) | `types.py`, `client.py`, 3 approach files | Low |
| 2 | Effective Recall metric (C) | `evaluator.py`, `generate_report.py` | Low |
| 3 | Force Decision (A) | `client.py`, `config.py`, `engine.py`, `system_prompt.yaml`, `vulnhunterx.py`, `run_benchmark.py` | Medium |
| 4 | SARIF codeFlows parsing (D1) | `types.py`, `sarif/parser.py` | Low |
| 5 | SlicedContextExtractor (D2+D3) | `context/extractor.py`, `approaches/base.py`, `llm/prompts.py`, `vulnhunterx.py`, `run_benchmark.py` | Medium |
| 6 | Juliet verification (E) | `setup_datasets.py`, fixture file | Low |
| 7 | DiverseVul adapter (F) | New `diversevul_adapter.py`, `setup_datasets.py`, `run_benchmark.py`, fixture | Medium |

---

## Key Files Reference

| File | Purpose in Plan |
|------|----------------|
| `src/vuln_hunter_x/llm/client.py:55,114,182,255` | Force decision, token reading |
| `src/vuln_hunter_x/core/types.py:99,28` | Add `tokens_used`/`cost_usd` to Verdict; `dataflow_path` to Finding |
| `src/vuln_hunter_x/sarif/parser.py:86` | Parse `codeFlows` from SARIF results |
| `src/vuln_hunter_x/context/extractor.py` | New `SlicedContextExtractor` class |
| `src/vuln_hunter_x/llm/prompts.py` | Include dataflow_path in user prompt |
| `src/vuln_hunter_x/verification/engine.py` | Pass `force_decision` to LLMClient |
| `src/vuln_hunter_x/core/config.py` | Add `force_decision` config field |
| `config/prompts/system_prompt.yaml` | Soften NMD preference instruction |
| `benchmarks/metrics/evaluator.py:82,264` | Add `nmd_tp_count`, `effective_recall` |
| `benchmarks/scripts/generate_report.py:57,66` | Add Eff. Recall column |
| `benchmarks/approaches/vulnhunterx.py` | Add `force_decision`, `use_slicing` params |
| `benchmarks/approaches/base.py` | Add slicing option to `_SnippetContextExtractor` |
| `benchmarks/scripts/run_benchmark.py:378,455` | Add DiverseVul dataset, force_decision flag |
| `benchmarks/adapters/diversevul_adapter.py` | New file |
| `benchmarks/fixtures/diversevul_sample.json` | New file |
