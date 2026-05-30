# VulnHunterX Benchmark: Research Notes

A living rationale document for the benchmark framework — papers reviewed, design decisions, cost model, evaluation strategy. Read this when you need to understand *why* the harness is shaped the way it is, or when you propose a change that touches sampling, metrics, or dataset selection.

Status labels on every design decision:

- **[Implemented]** — shipped and used by default.
- **[Partial]** — implemented but with documented limitations.
- **[Planned]** — design captured here, not yet in code.

---

## 1. Papers Reviewed

### LLM4FPM — arXiv:2411.03079 (Nov 2024)

*"Utilizing Precise and Complete Code Context to Guide LLM in Automatic False Positive Mitigation."* The most directly relevant prior work; evaluates LLM-based SAST FP reduction on Juliet C/C++ at scale.

- 7,194 warnings across 7 CWEs, Qwen2.5-32B (local).
- 5-turn dialogue per warning, ~6,848 tokens total (~912 input).
- eCPG-guided code slices reduce input size while preserving vulnerability context.
- At GPT-4 pricing (~$0.384/warning) the same evaluation would cost ~$2,758 — only feasible with a local model.
- 7 CWEs: 121, 122, 369, 401, 416, 457, 476.

**Impact:** token-cost model, Juliet per-CWE sampling strategy, code-slicing motivation.

### SecLLMHolmes — arXiv:2312.12575 (IEEE S&P 2024)

*"LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities in Code."* Hand-crafted 228-scenario benchmark across 8 CWEs.

- 6 scenarios per CWE × 3 difficulty levels (easy/medium/hard).
- 8 CWEs from MITRE Top 25 (2023): 787, 79, 89, 416, 22, 476, 190, 77.
- Inputs truncated to 6,144 tokens (PaLM-2 context bottleneck).
- Frontier LLMs (GPT-4, Claude) cap at ~40% accuracy.

**Impact:** CWE selection for `BENCHMARK_CWES` (cross-paper comparability); motivation for multi-turn over single-shot.

### CASTLE — arXiv:2503.09433 (TASE 2025)

*"Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE Detection."* Micro-benchmark designed to avoid Juliet's weaknesses for LLM evaluation.

- 250 programs total: 10 per CWE (6 vulnerable + 4 clean), 25 CWEs.
- 42 lines / ~463 tokens per program on average.
- Avoids Juliet because files can exceed 3,000 lines.
- Spans 25 MITRE Top-25 CWEs (2023–2024).

**Impact:** confirms per-CWE caps (10–20 entries) as the academic norm; motivates 8 KB code-snippet cap in adapters.

### ZeroFalse — arXiv:2510.02534 (Oct 2025)

*"ZeroFalse: Improving Precision in Static Analysis with LLMs."* LLM-based FP reduction on Java OWASP Benchmark.

- 1,974 CodeQL alerts (1,449 TP / 525 FP) across 9 web-app CWEs.
- Zero-shot outperforms few-shot; chain-of-thought adds marginal gains.
- Real-world validation on 58 additional alerts.

**Impact:** validates zero-shot as a baseline; motivates the `--max-iterations 1` single-turn baseline and the `zero-shot` ablation variant.

### CISC — ACL 2025 Findings (paper 1030)

*"Self-Consistency with Confidence for LLM-Based Code Review."* Self-consistency voting weighted by confidence.

- Same accuracy as standard self-consistency with **46% fewer LLM samples**.
- Temperature-0.7 majority vote across N responses outperforms single forced re-prompt.
- Ties broken conservatively (safer verdict).

**Impact:** design of the optional `force_decision_samples` parameter — when > 1, N parallel forced-decision calls vote by majority.

### LLMxCPG — arXiv:2507.16585 (USENIX Security 2025)

*"Code Property Graph-Guided LLM for Vulnerability Detection."* CPG-based slicing for LLM input reduction.

- 68–91% code reduction while preserving vulnerability-relevant context.
- Improves both precision and recall vs. full-function input.
- Requires CodeQL data-flow analysis to build the CPG.

**Impact:** motivates `SlicedContextExtractor` (regex-based today; CPG planned).

### Sifting the Noise — arXiv:2601.22952

*"A Comparative Study of LLM Agents in Vulnerability False Positive Filtering."* Multi-agent LLM pipelines for SAST FP reduction.

- Aider + DeepSeek at $0.003/task vs. $0.187 for the most expensive agent.
- Fixed-seed random sampling of 50 real-world alerts (31 FP / 19 TP).
- NMD ("inconclusive") responses are a major source of effective recall degradation.

**Impact:** fixed-seed sampling recommendation; motivates `nmd_handling` and the `effective_recall` metric; cost-conscious model selection.

### D2A Quality Study — ICSE 2023

*"An Empirical Study of Deep Learning Models for Vulnerability Detection."* Dataset-quality analysis of popular vulnerability benchmarks.

- D2A consistency score: **0.531** (random-guess level).
- ~57 duplicate functions per unique function (label leakage risk).
- Recommends DiverseVul as a higher-quality alternative.

**Impact:** chose **DiverseVul** as the real-world C/C++ dataset (see § 2.2).

### Java Juliet Subset — arXiv:2405.15614 (May 2024)

Balanced-subset evaluation of LLMs on Java Juliet 1.3.

- 578 files selected from 15,174 (34 per CWE × 17 CWEs: 17 TP + 17 FP).
- Explicit rationale: "Due to the high cost of running LLMs, we cannot experiment with all files."
- ~$0.06/file, $34.58 total for 578 files with one strategy.

**Impact:** confirms 50/50 TP/FP balance for Juliet; cost-per-entry reference for Java.

---

## 2. Design Decisions

### 2.1 Juliet sampling strategy — **[Implemented]**

**Problem.** Juliet has 64K test cases. Commercial-LLM cost for full Juliet is prohibitive (~$2,200 at GPT-4o pricing). The previous cumulative `--limit N` could pull all N entries from a single alphabetically-first CWE.

**Decision.** Stratified per-CWE sampling with balanced TP/FP via `--juliet-per-cwe`.

| Preset             | `--juliet-per-cwe` | CWEs | Total entries | Est. cost (GPT-4o) |
| ------------------ | ------------------ | ---- | ------------- | ------------------ |
| Quick              | 10                 | 8    | 80            | ~$2.70             |
| Standard (default) | 20                 | 8    | 160           | ~$5.50             |
| Full               | 0                  | ~15  | ~7,000+       | local model only   |

**`BENCHMARK_CWES`** (8 CWEs, cross-paper comparable):

| CWE     | Name                          | In SecLLMHolmes | In LLM4FPM |
| ------- | ----------------------------- | :-------------: | :--------: |
| CWE-416 | Use After Free                |       yes       |    yes     |
| CWE-476 | NULL Pointer Dereference      |       yes       |    yes     |
| CWE-190 | Integer Overflow              |       yes       |     —      |
| CWE-787 | Out-of-Bounds Write           |       yes       |     —      |
| CWE-125 | Out-of-Bounds Read            |       yes       |     —      |
| CWE-401 | Memory Leak                   |        —        |    yes     |
| CWE-457 | Use of Uninitialized Variable |        —        |    yes     |
| CWE-134 | Uncontrolled Format String    |       yes       |     —      |

Rationale: all 8 have CodeQL rules; they span both SecLLMHolmes and LLM4FPM (cross-paper comparison); they cover the most impactful memory-safety and injection CWEs from MITRE Top 25.

### 2.2 DiverseVul instead of D2A — **[Implemented, final]**

**Problem.** Early planning referenced D2A as the real-world C/C++ dataset.

**Decision.** Use DiverseVul (RAID 2023). D2A is not referenced anywhere in the benchmark code.

| Criterion                | D2A                    | DiverseVul                       |
| ------------------------ | ---------------------- | -------------------------------- |
| Consistency score        | 0.531 (near random)    | not reported (CVE-backed)        |
| Duplicate functions      | ~57 per unique func    | deduplicated                     |
| Vulnerable functions     | 21K                    | 18,945                           |
| Non-vulnerable functions | 1.2M                   | 330,492                          |
| CWEs                     | varied                 | 150                              |
| Label source             | Infer tool (noisy)     | real CVEs (ground truth)         |
| Availability             | restricted             | GitHub `wagner-group/diversevul` |

### 2.3 NMD handling and self-consistency

**Problem.** High NMD rates make reported Recall optimistic — NMD entries are excluded from P/R/F1.

**Decision.**

- **Force decision** — **[Implemented]**. When the LLM returns NMD at `max_iterations`, send one forced re-prompt requiring TP or FP. If still NMD, convert to FP with Low confidence (conservative).
- **Self-consistency voting (CISC)** — **[Optional]**. Set `force_decision_samples > 1` to run N parallel forced-decision calls and take a majority vote. By default `force_decision_samples = 1` (no voting); CISC reports `N = 3` achieves the same accuracy as standard self-consistency with 46% fewer samples.

### 2.4 Code slicing

**Problem.** Full function bodies (100+ lines) inflate cost; LLM4FPM shows that precise slices improve accuracy and reduce tokens.

**Decision.**

- **Phase 1, regex-based** — **[Implemented]**. `SlicedContextExtractor` parses the SARIF message for the key variable, then returns lines referencing it ± a context window around the flagged line. Falls back to full code when no variable can be extracted.
- **Phase 2, CPG-guided** — **[Planned]**. Use CodeQL data-flow libraries (LLMxCPG approach); expected 68–91% input reduction while preserving vulnerability-relevant context.

### 2.5 Effective recall metric — **[Implemented]**

**Problem.** Standard Recall excludes NMDs. When NMD rate is high and NMDs fall on true positives, Recall flatters.

**Decision.** Add an `effective_recall`:

```
Eff. Recall = TPs confirmed / (TPs confirmed + TPs missed + NMDs that were TPs)
```

This metric penalizes NMDs on real vulnerabilities, giving an honest picture of TP preservation under `nmd_handling=exclude`.

### 2.6 Token and cost tracking — **[Implemented]**

Read `response.usage` after each LiteLLM completion; use `litellm.completion_cost()` for cost estimation; accumulate tokens and cost across turns; propagate through `Verdict` → `BenchmarkResult` → `ApproachMetrics`.

### 2.7 Three-layer logging — **[Implemented]**

Keep the terminal clean while preserving full audit trails:

1. **Terminal (stderr)** — WARNING+ only; progress bar stays clean.
2. **File `benchmark.log`** — full DEBUG/INFO; LiteLLM messages captured here.
3. **JSONL `findings.jsonl`** — one structured record per evaluated entry; queryable with `jq`.

---

## 3. Token and Cost Reference

Based on LLM4FPM data (Juliet C/C++, 5-turn dialogue, GPT-4-equivalent pricing):

| Stage                 | Tokens |
| --------------------- | ------ |
| Input per turn (avg)  | ~912   |
| Output per turn (avg) | ~460   |
| Total over 5 turns    | ~6,848 |

At GPT-4o pricing ($0.005 / 1K input, $0.015 / 1K output):

- ~$0.005–$0.034 per Juliet entry. The range reflects per-CWE variance — memory-safety rules (CWE-416, -787) typically consume 50–80% more tokens than format-string or injection rules due to multi-hop data-flow queries.
- 160-entry standard Juliet run: **~$5.50**.
- 228-entry SecLLMHolmes run: **~$7.76**.

At Qwen3-Max via Aliyun DashScope (~$0.003 / 1K total tokens):

- Per-entry cost: **~$0.002–$0.021**.
- 160-entry standard Juliet run: **~$0.33–$3.36**.

---

## 4. Recommended Evaluation Protocol

For cross-paper comparability:

```bash
# 1. Quick validation (no API cost)
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach raw-sast --limit 10

# 2. Standard SecLLMHolmes (228 entries, 8 CWEs)
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all

# 3. Standard Juliet (160 entries, 8 CWEs × 20, balanced TP/FP)
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach all --juliet-per-cwe 20

# 4. DiverseVul sample (real-world CVE-backed)
python benchmarks/scripts/run_benchmark.py \
    --dataset diversevul --approach all --limit 200

# 5. Full report
python benchmarks/scripts/generate_report.py \
    --run-dir benchmarks/results/<run_dir>
```

### Comparing against LLM4FPM (arXiv:2411.03079)

LLM4FPM uses 7 CWEs: 121, 122, 369, 401, 416, 457, 476. Four (401, 416, 457, 476) are in our `TARGET_CWES`. To enable full coverage, add `"CWE121", "CWE122", "CWE369"` to `TARGET_CWES` in [benchmarks/adapters/juliet_adapter.py](adapters/juliet_adapter.py).

```bash
# Partial replication (4 of 7 LLM4FPM CWEs)
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach vulnhunterx \
    --juliet-per-cwe 0
    # add: --model ollama/qwen2.5:32b   # local model strongly recommended
```

Full LLM4FPM replication (all 7,194 warnings across 7 CWEs) requires a local model — frontier-API cost would exceed $2,700.

### Comparing against SecLLMHolmes (arXiv:2312.12575)

SecLLMHolmes uses a single LLM call (no multi-turn) with a 6,144-token input cap. The closest match in our harness is:

```bash
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes \
    --approach vulnhunterx \
    --max-iterations 1
```

The standard `vulnhunterx` run adds multi-turn context expansion on top — which is the VulnHunterX improvement being measured.

---

## 5. Planned Future Work

| Feature                              | Motivation                                  | Status      |
| ------------------------------------ | ------------------------------------------- | ----------- |
| CPG-guided slicing (Phase 2)         | LLMxCPG: 68–91% code reduction              | **Planned** — needs CodeQL data-flow |
| Self-consistency voting (CISC)       | 46% fewer samples for same accuracy         | **Optional** via `force_decision_samples` |
| Model matrix (Ollama/GPT/DeepSeek)   | Apples-to-apples cross-model comparison (Track 1) | **In progress** — see § 6.1 |
| OpenVuln/ZeroFalse adapter           | Real CodeQL alerts + human TP/FP (best Track-1 fit) | **In progress** — see § 6.3 |
| `security-rules` adapter             | Finding-shaped Go/PHP/JS coverage for this repo's rules | **In progress** — see § 6.4 |
| DiverseVul → Track-2 (recall-only)   | ≈60% label accuracy; not FP-reduction       | **In progress** — see § 6.2 |
| Confidence-calibration charts        | Validate High/Medium/Low confidence signals | **Planned** |
| Youden Index + MCC scoring           | Match OWASP scorecard + SastBench paper     | **Planned** |
| PrimeVul adapter                     | Cleaner C/C++ Track-2 labels than DiverseVul | **Planned** — see § 6.2 |
| SecBench.js / SARD-PHP / gosec       | Per-language Track-1 supplements            | **Planned** — see § 6.4 |
| SastBench REST `/analyze` harness    | Submit to SastBench leaderboard             | **Planned** — data gated, see § 6.5 |

### Web-language coverage via OWASP Benchmark

VulnHunterX targets memory-safety C/C++ today; the existing adapters reflect that. To exercise the web rule packs (CodeQL `java-queries`, `python-queries`, Semgrep web rules), we ship adapters for the OWASP Benchmark Project suites:

- **BenchmarkJava** v1.2 — ~2,740 cases, 11 CWE categories (SQLi, XSS, path traversal, command injection, LDAP, XPath, weak random, weak hash, trust boundary, insecure cookie, crypto). GPL-2.0.
- **BenchmarkPython** v0.1 — ~1,230 cases over the same taxonomy. GPL-3.0.

Both ship a CSV manifest (`expectedresults-<version>.csv`) keyed by `BenchmarkTest#####` filename + CWE — straightforward adapter parsing. Datasets are cloned into `benchmarks/datasets/` at runtime; **VulnHunterX project code stays MIT**, GPL applies only to the cloned test corpora (not vendored, not linked).

OWASP's official scorecard uses the **Youden Index** (TPR + TNR − 1, ×100). We currently report P/R/F1 + FP-reduction; Youden Index is queued for the scoring upgrade.

### Noisy real-world dataset — RealVuln (SastBench substitute)

To exercise the verifier on the SAST-FP-vs-CVE-TP setting it's deployed against (rather than function-level CVE labels), we add the **RealVuln Benchmark** ([kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark), MIT) — 796 findings across 26 Python web-framework repos, mixing real CVE TPs with curated FP traps.

**SastBench substitution context.** RealVuln was adopted as a substitute for **SastBench** (arXiv:2601.02941), whose public repository URL was not findable at integration time. RealVuln has the same shape (real CVE TPs + curated FP traps) and a documented JSON schema (`is_vulnerable: bool` + `primary_cwe` + `location.{start_line,end_line,function}` + `evidence.{source,cve_id}`). The adapter is schema-compatible enough that swapping SastBench in later — if its repo becomes available — is a small change.

Snippet extraction is best-effort: the adapter reads function lines from a per-repo working tree at `benchmarks/datasets/realvuln/_repos/<repo_id>/`. The user manages checkout to each finding's `commit_sha`. Findings without a working tree are tagged `metadata.snippet_kind = "missing"`.

---

## 6. Dataset Selection Guide — what to benchmark on, and why

This section records a web-verified (May 2026) review of which datasets fit
VulnHunterX's actual task, and **why function-level CVE datasets (DiverseVul,
CVEfixes) produced poor, misleading benchmark numbers**. Every dataset below was
verified against its canonical repo/paper; citations are in § References.

### 6.1 The task framing — two tracks, kept separate

VulnHunterX is a **finding-level SAST false-positive reducer**: given a static
analysis *alert* (rule_id + file + sink line + dataflow + guided questions), it
decides True Positive vs False Positive. It is **not** a function-level
vulnerability *detector*. These are different tasks and demand different datasets.
The benchmark therefore reports two tracks that are **never folded into one
headline P/R/F1**:

| Track | Question answered | Datasets |
| ----- | ----------------- | -------- |
| **Track 1 — FP-reduction (primary)** | Given a real SAST alert, is it TP or FP? | OpenVuln/ZeroFalse, OWASP Java/Python, RealVuln, SecLLMHolmes, Juliet, `security-rules` |
| **Track 2 — detection (secondary, caveated)** | Is this whole function vulnerable? | DiverseVul (recall-only), PrimeVul (future) |

The cross-model comparison (Ollama / GPT / DeepSeek) is computed on **Track 1
only**, so model rankings reflect the deployed task rather than detection noise.

### 6.2 Why DiverseVul & CVEfixes benchmarked badly — **[Diagnosed]**

Observed in `benchmarks/results/`: on DiverseVul, `vulnhunterx` showed **recall
0.6 / TP-preservation 0.6** (dropping 40% of real vulns) and a per-CWE bucket at
**precision 0.09** (near-random). Root causes are structural, not tuning:

1. **Task mismatch.** The DiverseVul adapter emits a whole function with
   `start_line=1`, **no sink, no dataflow**, and a `rule_id` *synthesized from the
   CWE*. The verifier — built around a specific alert location — reasons blind.
   This is the function-level detection task that SecLLMHolmes showed frontier
   LLMs cap at ~40% accuracy on.
2. **Label-semantics mismatch.** `target=0` (non-vulnerable function) is mapped to
   `LABEL_FP`, but a non-vulnerable function is **not** a SAST false positive —
   SAST never fires on most of them. Scoring on them measures classification, not
   FP-reduction.
3. **No real SAST stage.** The `raw-sast` baseline marks every entry TP (it echoes
   the label; it does not run CodeQL/Semgrep), so `fp_reduction_rate` is
   structurally unmeasurable on these datasets.
4. **Label noise (verified).** DiverseVul's measured label accuracy is **≈60%**
   (PrimeVul's independent manual analysis, matching DiverseVul's own noise
   analysis); Croft et al. (ICSE 2023) found **20–71% of labels inaccurate** and
   **17–99% duplicated** across real-world vuln datasets. CVEfixes is worse: labels
   are fix-commit-derived at file/method level (`file_change.code_before/code_after`,
   link table `fixes`, CWE in `cwe_classification`), so the fix is often in a
   *different* function than the flagged one (tangled-commit noise), and it ships
   **no negatives at all**.

**Decision:** DiverseVul → Track-2, **recall / TP-preservation only**, excluded
from the headline and the model matrix. **CVEfixes is dropped** (strictly worse for
this tool). The *correct* (heavy) way to use function-level data for FP-reduction
is to run real CodeQL/Semgrep over each function, keep only functions where a tool
actually fires, then score the verifier against the function label — tracked as
future work. **PrimeVul** ([arXiv:2403.18624](https://arxiv.org/abs/2403.18624),
86–92% label accuracy, C/C++ only) is the cleaner Track-2 successor — but note a
SOTA 7B model drops from 68% F1 (BigVul) to 3% F1 (PrimeVul); low absolute scores
on PrimeVul are the *honest* signal, not a regression.

### 6.3 Verified finding-shaped (Track-1) inventory

| Dataset | Lang | Shape | Size | License | Status |
| ------- | ---- | ----- | ---- | ------- | ------ |
| **OpenVuln / ZeroFalse** | Java | **real CodeQL SARIF alerts + human TP/FP** | 58 (23 TP / 35 FP) | MIT | the exact shape of our pipeline — **highest-fidelity real set found** |
| **OWASP Java/Python** | Java, Python | test-case TP/FP CSV; you run the tool | ~2,740 / ~1,230 | GPL-2.0 / 3.0 | wired |
| **RealVuln** | Python web | per-finding TP + curated FP traps; ships Semgrep/Snyk/Sonar results | 796 | MIT | wired |
| **SecLLMHolmes** | C/C++, Python | hand-crafted bad/good pairs | ~228 | MIT | wired |
| **Juliet** | C, C++ | synthetic `bad()`/`good()` | 64K | CC0 | wired |
| **`security-rules`** | Go, PHP, JS, Python | in-repo `vuln`/`clean` pairs per custom rule | 14 pairs | (repo) | planned — validates this repo's own new rules |

### 6.4 Go / PHP / JavaScript coverage — the gap and the verified fix

VulnHunterX now ships custom rules for Go/PHP/JS, but **no mainstream dataset
covers them finding-shaped** — verified non-existent: OWASP Benchmark for
Go/PHP/JS, and NIST SARD Go/JS/TS suites. The verified, recognized fix is to use
**SAST rule test fixtures as ground truth** (Semgrep `// ruleid:` / `// ok:`
annotations with `semgrep --test`; CodeQL `.expected` files with `codeql test
run`). The in-repo [tests/fixtures/security-rules/](../tests/fixtures/security-rules/)
already follows this pattern, so the `security-rules` adapter is the first instance.
Per-language verified supplements (roadmap):

- **JavaScript** — [SecBench.js](https://github.com/cristianstaicu/SecBench.js)
  (ICSE 2023): 600 real server-side JS vulns with **file+line `sinkLocation`** +
  fix commit (prototype pollution, path traversal, command injection, ReDoS, code
  injection) — maps directly to a SARIF region.
- **PHP** — NIST SARD PHP suites
  ([103](https://samate.nist.gov/SARD/test-suites/103) /
  [114](https://samate.nist.gov/SARD/test-suites/114)): tens of thousands of
  CWE-labeled synthetic XSS/SQLi cases, public domain — **same shape as Juliet**, so
  the adapter is largely a JulietAdapter clone.
- **Go** — [gosec](https://github.com/securego/gosec) `testutils`/`testdata`
  (Apache-2.0): finding-shaped rule samples with expected-issue counts, category-
  aligned with our Go rules; small N per rule.
- Multi-language real CVE volume (Track-2 only, function-level/noisy): CVEfixes (JS
  46,802 / PHP 4,758 / Go 1,880) and [CrossVul](https://zenodo.org/records/4734050)
  (40+ langs) — usable for recall studies, **not** for precision/FP-reduction.

### 6.5 Datasets evaluated and rejected

- **SastBench** ([arXiv:2601.02941](https://arxiv.org/abs/2601.02941)) — ideal shape
  (real CVE TPs + Semgrep FPs, 38 langs) but the **public data is gated/early-access**;
  RealVuln remains the substitute until it ships.
- **D2A** (IBM, Apache-2.0) — large Infer alert-level set, but **archived (Jul 2024)**,
  C/C++/Infer-only, and Croft et al. rate >⅔ of its labels inaccurate
  (consistency 0.531). Only worth wiring if Infer support is added.
- **CASTLE** ([arXiv:2503.09433](https://arxiv.org/abs/2503.09433)) — clean balanced
  micro-benchmark but **C-only**; does not help the Go/PHP/JS gap.

---

## References

- [LLM4FPM](https://arxiv.org/abs/2411.03079) — Su F. et al. (2024). Juliet C/C++ multi-turn LLM FP mitigation.
- [SecLLMHolmes](https://arxiv.org/abs/2312.12575) — Ullah S., Han M., et al. (2024). Hand-crafted 228-scenario benchmark. IEEE S&P 2024.
- [CASTLE](https://arxiv.org/abs/2503.09433) — Bouzenia M., et al. (2025). 250-program micro-benchmark for SAST + LLM. TASE 2025.
- [ZeroFalse](https://arxiv.org/abs/2510.02534) — Mohajer M. M., et al. (2025). Zero-shot LLM FP reduction on OWASP.
- [CISC](https://aclanthology.org/2025.findings-acl.1030.pdf) — Li B., et al. (2025). Self-consistency with confidence for LLM code review. ACL 2025 Findings.
- [LLMxCPG](https://arxiv.org/abs/2507.16585) — Risse N., et al. (2025). Code Property Graph-guided LLM slicing. USENIX Security 2025.
- [Sifting the Noise](https://arxiv.org/abs/2601.22952) — Comparative study of LLM agents for SAST FP filtering.
- [D2A Quality Study](https://rolandcroft.github.io/assets/publications/ICSE_23.pdf) — Croft R., et al. (2023). Dataset quality analysis. ICSE 2023.
- [Java Juliet Subset](https://arxiv.org/abs/2405.15614) — Balanced subset sampling for LLM evaluation (May 2024).
- [DiverseVul](https://github.com/wagner-group/diversevul) — Chen Y., et al. (2023). 349K C/C++ functions with CVE-backed labels. RAID 2023.
- [OWASP Benchmark Project](https://owasp.org/www-project-benchmark/) — synthetic SAST test suites with CSV ground truth ([Java](https://github.com/OWASP-Benchmark/BenchmarkJava), [Python](https://github.com/OWASP-Benchmark/BenchmarkPython)).
- [SastBench](https://arxiv.org/abs/2601.02941) — agentic SAST triage benchmark; public repo URL not located at integration time.
- [RealVuln Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) — real CVE TPs + FP traps for Python web frameworks (MIT); used as the SastBench substitute.
- [Juliet C/C++ 1.3.1](https://samate.nist.gov/SARD/test-suites/116) — NIST SARD test suite.
- [ZeroFalse / OpenVuln](https://github.com/mhsniranmanesh/ZeroFalse) — 58 real CodeQL SARIF alerts with human TP/FP labels across 7 Java projects (MIT).
- [PrimeVul](https://github.com/DLVulDet/PrimeVul) — Ding Y., et al. (2024). Re-labeled C/C++ vuln dataset (86–92% label accuracy); ICSE 2025. [arXiv:2403.18624](https://arxiv.org/abs/2403.18624).
- [Croft et al. Data Quality](https://arxiv.org/abs/2301.05456) — 20–71% of vuln-dataset labels inaccurate, 17–99% duplicated. ICSE 2023.
- [SecBench.js](https://github.com/cristianstaicu/SecBench.js) — 600 real server-side JS vulns with file+line sink locations. ICSE 2023.
- [NIST SARD PHP suites](https://samate.nist.gov/SARD/test-suites) — CWE-labeled synthetic PHP cases ([103](https://samate.nist.gov/SARD/test-suites/103), [114](https://samate.nist.gov/SARD/test-suites/114)); public domain. SARD covers C/C++/Java/PHP/C# only.
- [gosec](https://github.com/securego/gosec) — Go SAST with finding-shaped rule testdata (Apache-2.0).
- [CVEfixes](https://github.com/secureIT-project/CVEfixes) — multi-language CVE-fix SQLite DB; function-level/fix-commit labels (Track-2 only). [arXiv:2107.08760](https://arxiv.org/abs/2107.08760).
- [CrossVul](https://zenodo.org/records/4734050) — 40+ language file-level vuln/patch pairs. ESEC/FSE 2021.
- Semgrep [rule testing](https://semgrep.dev/docs/writing-rules/testing-rules) & CodeQL [query testing](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/testing-custom-queries) — `ruleid:`/`ok:` and `.expected` fixtures as ground truth.
