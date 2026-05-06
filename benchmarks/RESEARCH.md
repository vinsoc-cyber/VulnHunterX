# VulnHunterX Benchmark: Research Notes

This document records the academic literature reviewed, key findings, and design decisions
made to improve the VulnHunterX benchmark framework. It is meant to be a living reference
for contributors who want to understand *why* things are designed the way they are.

---

## 1. Papers Reviewed

### LLM4FPM (arXiv:2411.03079, Nov 2024)
**"Utilizing Precise and Complete Code Context to Guide LLM in Automatic False Positive Mitigation"**

The most directly relevant paper. Evaluates LLM-based SAST FP reduction on Juliet C/C++ at scale.

Key findings:
- Evaluates **7,194 warnings** across 7 CWEs from Juliet C/C++ using Qwen2.5-32B (local, free).
- Multi-turn dialogue with **5 turns** per warning consumes ~6,848 tokens total (~912 input tokens).
- Provides the only published per-entry token budget data for Juliet C/C++ with multi-turn LLMs.
- Code slices (eCPG-guided) dramatically reduce input size while preserving vulnerability context.
- At GPT-4 pricing (~$0.384/warning), evaluating 7,194 entries would cost ~$2,758 — only feasible with a local model.

CWEs selected (7): CWE-121, CWE-122, CWE-369, CWE-401, CWE-416, CWE-457, CWE-476.

**Impact on VulnHunterX:** Token cost model; Juliet per-CWE sampling strategy; code slicing motivation.

---

### SecLLMHolmes (arXiv:2312.12575, IEEE S&P 2024)
**"LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities in Code"**

Hand-crafted benchmark with 228 code scenarios across 8 CWEs.

Key findings:
- Uses **6 scenarios per CWE** at 3 difficulty levels (easy/medium/hard), not Juliet.
- 8 CWEs selected from MITRE Top 25 (2023): CWE-787, CWE-79, CWE-89, CWE-416, CWE-22, CWE-476, CWE-190, CWE-77.
- Truncates all inputs to 6,144 tokens (Palm2 context window was the bottleneck).
- State-of-the-art LLMs (GPT-4, Claude) achieve at best ~40% accuracy — worse than expected.

**Impact on VulnHunterX:** CWE selection for BENCHMARK_CWES (overlap with LLM4FPM for cross-benchmark comparability); motivation for multi-turn verification over single-shot.

---

### CASTLE (arXiv:2503.09433, TASE 2025)
**"Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE Detection"**

Micro-benchmark explicitly designed to avoid Juliet's weaknesses for LLM evaluation.

Key findings:
- **250 programs** total: 10 per CWE (6 vulnerable + 4 non-vulnerable), 25 CWEs.
- Average 42 lines per program (max 164). ~463 tokens avg per program.
- Explicitly avoids Juliet because files can exceed 3,000 lines — causing token cost explosion
  and making fair comparison with formal verifiers impossible.
- Covers 25 CWEs from MITRE Top 25 (2023–2024) spanning memory, injection, and crypto.

**Impact on VulnHunterX:** Confirmed that per-CWE caps (10–20 entries) are the academic norm.
Motivation for capping code snippets to 8,000 chars in adapters.

---

### ZeroFalse (arXiv:2510.02534, Oct 2025)
**"ZeroFalse: Improving Precision in Static Analysis with LLMs"**

LLM-based FP reduction on Java (OWASP Benchmark), not C/C++ Juliet.

Key findings:
- 1,974 CodeQL-triggered alerts (1,449 TP / 525 FP) across 9 web-application CWEs.
- Zero-shot prompting outperforms few-shot; chain-of-thought adds marginal gains.
- Real-world validation on 58 additional alerts.

**Impact on VulnHunterX:** Confirmed zero-shot prompting as a valid baseline; motivation for
`vulnhunterx` with `--max-iterations 1` as a single-turn baseline and `ablation-zero` in the ablation study.

---

### CISC (ACL 2025, aclanthology.org/2025.findings-acl.1030.pdf)
**"Self-Consistency with Confidence for LLM-Based Code Review"**

Self-consistency voting for LLM verdicts using confidence-weighted majority.

Key findings:
- Achieves same accuracy as standard self-consistency with **46% fewer LLM samples**.
- Majority vote across N responses at temperature=0.7 is more reliable than single forced re-prompt.
- Ties broken conservatively (safer verdict).

**Impact on VulnHunterX:** Design of the optional `force_decision_samples` parameter —
when `> 1`, runs N parallel forced-decision calls and takes majority vote.

---

### LLMxCPG (USENIX Security 2025, arXiv:2507.16585)
**"Code Property Graph-Guided LLM for Vulnerability Detection"**

CPG-based code slicing for LLM input reduction.

Key findings:
- CPG-based slicing reduces code by **68–91%** while preserving vulnerability-relevant context.
- Significant improvement in both precision and recall compared to full-function input.
- Requires CodeQL data-flow analysis to build the CPG.

**Impact on VulnHunterX:** Motivation for `SlicedContextExtractor` (Phase 1: regex-based variable
tracking). CPG slicing is a planned Phase 2 enhancement using CodeQL data-flow libraries.

---

### Sifting the Noise (arXiv:2601.22952)
**"A Comparative Study of LLM Agents in Vulnerability False Positive Filtering"**

Multi-agent LLM pipelines for SAST FP reduction.

Key findings:
- Aider+DeepSeek cheapest at **$0.003/task** vs $0.187 for the most expensive agent.
- Fixed-seed random sampling of 50 real-world alerts (31 FP / 19 TP) for reproducibility.
- NMD ("inconclusive") responses are a major source of effective recall degradation.

**Impact on VulnHunterX:** Fixed-seed sampling recommendation; motivation for
`nmd_handling` and `effective_recall` metric; cost-conscious model selection.

---

### D2A Quality Study (ICSE 2023, rolandcroft.github.io/assets/publications/ICSE_23.pdf)
**"An Empirical Study of Deep Learning Models for Vulnerability Detection"**

Dataset quality analysis of popular vulnerability benchmarks.

Key findings:
- D2A has **consistency score of only 0.531** (random-guess level).
- D2A has an average of **57 duplicate functions per unique function** — label leakage risk.
- DiverseVul is recommended as a higher-quality alternative.

**Impact on VulnHunterX:** Decision to use **DiverseVul** instead of D2A as the real-world C/C++
dataset. DiverseVul (RAID 2023) has 18,945 vulnerable + 330,492 non-vulnerable functions, 150 CWEs,
real CVE-backed labels, and no known quality issues.

---

### Java Juliet Subset Study (arXiv:2405.15614, May 2024)

Evaluates LLMs on a balanced subset of Java Juliet 1.3.

Key findings:
- From 15,174 files, selects **578 files** (34 per CWE × 17 CWEs: 17 TP + 17 FP).
- Explicit rationale: "Due to the high cost of running LLMs, we cannot experiment with all files."
- Cost: ~$0.06/file, $34.58 total for 578 files with one strategy.

**Impact on VulnHunterX:** Confirmed 50/50 TP/FP balance as the standard for Juliet evaluation;
cost-per-entry reference for Java; rationale language for subset selection.

---

## 2. Key Design Decisions

### 2.1 Juliet Sampling Strategy

**Problem:** Juliet has 64K test cases. Running all with a commercial LLM is cost-prohibitive
(~$2,200 at GPT-4o pricing). The old `--limit N` was cumulative across CWEs, meaning all N
entries could come from a single CWE (CWE-119 alphabetically first).

**Decision:** Stratified per-CWE sampling with balanced TP/FP.

| Preset             | `--juliet-per-cwe` | CWEs | Total entries | Est. cost (GPT-4o) |
| ------------------ | ------------------ | ---- | ------------- | ------------------ |
| Quick              | 10                 | 8    | 80            | ~$2.70             |
| Standard (default) | 20                 | 8    | 160           | ~$5.50             |
| Full               | 0                  | 15   | ~7,000+       | local model only   |

**BENCHMARK_CWES** (8 CWEs, cross-benchmark overlap with SecLLMHolmes + LLM4FPM):

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

**Rationale for 8-CWE selection:**
1. All 8 are in Juliet's `TARGET_CWES` (CodeQL rules exist).
2. They span SecLLMHolmes AND LLM4FPM — allowing cross-benchmark comparability.
3. They cover the most impactful memory-safety and injection CWEs from MITRE Top 25.

---

### 2.2 DiverseVul Instead of D2A

**Problem:** Early plans referenced D2A as the real-world C/C++ dataset.

**Decision:** Use DiverseVul (RAID 2023) instead.

| Criterion                | D2A                    | DiverseVul                       |
| ------------------------ | ---------------------- | -------------------------------- |
| Consistency score        | 0.531 (near random)    | Not reported (CVE-backed)        |
| Duplicate functions      | avg 57 per unique func | Deduplicated                     |
| Vulnerable functions     | 21K                    | 18,945                           |
| Non-vulnerable functions | 1.2M                   | 330,492                          |
| CWEs                     | varied                 | 150                              |
| Label source             | Infer tool (noisy)     | Real CVEs (ground truth)         |
| Public availability      | restricted             | GitHub (wagner-group/diversevul) |

---

### 2.3 Force Decision on NMD

**Problem:** High NMD rates in benchmark runs cause reported Recall to be misleadingly optimistic
because NMD entries are excluded from precision/recall computation.

**Decision:** Add a `force_decision` second turn — when the LLM returns NMD at max iterations,
send one forced re-prompt requiring a TP or FP verdict. If the forced response is still NMD,
convert to False Positive with Low confidence (conservative).

**Self-consistency mode** (from CISC, ACL 2025): Optionally run N parallel forced-decision calls
and take majority vote — achieves same accuracy as standard self-consistency with 46% fewer samples.

---

### 2.4 Code Slicing

**Problem:** LLM receives full function bodies (often 100+ lines). LLM4FPM shows that
precise code slices improve accuracy while reducing token cost.

**Phase 1 (implemented):** Regex-based `SlicedContextExtractor`:
- Extracts the key variable name from the SARIF message.
- Returns lines referencing that variable ± a context window around the flagged line.
- Falls back to full code when no variable can be extracted.

**Phase 2 (planned):** CPG-guided slicing via CodeQL data-flow libraries (LLMxCPG approach),
expected to reduce input by 68–91% while preserving all vulnerability-relevant context.

---

### 2.5 Effective Recall Metric

**Problem:** Standard Recall excludes NMD entries. When NMD rates are high and NMDs fall
disproportionately on true positives, reported Recall is misleadingly optimistic.

**Decision:** Add `effective_recall` to the report:

```
Eff. Recall = TPs confirmed / (TPs confirmed + TPs missed + NMDs that were TPs)
```

This metric penalizes NMDs on real vulnerabilities, giving a more honest picture of
TP preservation under the `nmd_handling=exclude` policy.

---

### 2.6 Token and Cost Tracking

**Design:** Read `response.usage` after each LiteLLM completion call; use
`litellm.completion_cost()` for cost estimation; accumulate tokens and cost across turns;
propagate through `Verdict` → `BenchmarkResult` → `ApproachMetrics`.

---

### 2.7 Logging Architecture

**Decision:** Three-layer logging to keep the terminal clean while preserving full audit trails:
1. **Terminal (stderr):** WARNING+ only — progress bar stays clean.
2. **File (`benchmark.log`):** Full DEBUG/INFO — LiteLLM messages captured here.
3. **JSONL (`findings.jsonl`):** One structured record per evaluated entry — queryable with `jq`.

---

## 3. Token Cost Reference

Based on LLM4FPM data (Juliet C/C++, 5-turn multi-turn, GPT-4 equivalent pricing):

| Stage                 | Tokens |
| --------------------- | ------ |
| Input per turn (avg)  | ~912   |
| Output per turn (avg) | ~460   |
| Total over 5 turns    | ~6,848 |

At GPT-4o pricing ($0.005/1K input, $0.015/1K output):
- ~$0.005–$0.034 per Juliet entry (wide range based on code length and turn count).
- 160-entry standard Juliet run: **~$5.50**.
- 228-entry SecLLMHolmes run: **~$7.76**.

At qwen3.5-122b-a10b via Aliyun DashScope (~$0.003/1K total tokens):
- Per-entry cost: **~$0.002–$0.021**.
- 160-entry standard Juliet run: **~$0.33–$3.36**.

---

## 4. Benchmark Strategy Summary

**Recommended evaluation protocol for cross-paper comparability:**

```bash
# 1. Quick validation (no API cost)
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach raw-sast --limit 10

# 2. Standard SecLLMHolmes run (228 entries, all 8 CWEs)
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes --approach all

# 3. Standard Juliet run (160 entries, 8 CWEs × 20, balanced TP/FP)
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach all --juliet-per-cwe 20

# 4. DiverseVul sample (real-world CVE-backed)
python benchmarks/scripts/run_benchmark.py \
    --dataset diversevul --approach all --limit 200

# 5. Full report
python benchmarks/scripts/generate_report.py \
    --run-dir benchmarks/results/<run_dir>
```

**For comparison with LLM4FPM** (arXiv:2411.03079):

LLM4FPM uses 7 CWEs: CWE-121, CWE-122, CWE-369, CWE-401, CWE-416, CWE-457, CWE-476.
Of these, 4 are in `TARGET_CWES` (CWE-401, CWE-416, CWE-457, CWE-476). To add full coverage,
add `"CWE121", "CWE122", "CWE369"` to `TARGET_CWES` in
[benchmarks/adapters/juliet_adapter.py](adapters/juliet_adapter.py).

```bash
# Partial replication (4 of 7 LLM4FPM CWEs, in TARGET_CWES):
# --juliet-per-cwe 0 disables per-CWE cap; --benchmark_cwes_only False uses all TARGET_CWES
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet \
    --approach vulnhunterx \
    --juliet-per-cwe 0 \
    # --model ollama/qwen2.5:32b   # local model strongly recommended — ~7K entries total
```

For exact LLM4FPM replication (all 7,194 warnings across all 7 CWEs), a local model is
required — at GPT-4o pricing the cost would exceed $2,700.

**For comparison with SecLLMHolmes** (arXiv:2312.12575):

```bash
# Single-turn baseline — matches SecLLMHolmes evaluation protocol (1 LLM call, no multi-turn)
python benchmarks/scripts/run_benchmark.py \
    --dataset secllmholmes \
    --approach vulnhunterx \
    --max-iterations 1
```

SecLLMHolmes uses a single LLM call (no multi-turn) with a 6,144-token input cap.
`vulnhunterx --max-iterations 1` is the closest match; the standard `vulnhunterx` run adds
multi-turn context expansion on top, which is the VulnHunterX improvement being measured.

---

## 5. Planned Future Work

| Feature                        | Motivation                                  | Complexity                       |
| ------------------------------ | ------------------------------------------- | -------------------------------- |
| CPG-guided slicing (Phase 2)   | LLMxCPG: 68–91% code reduction              | High (requires CodeQL data-flow) |
| Self-consistency voting (CISC) | 46% fewer samples for same accuracy         | Medium                           |
| DiverseVul per-CWE sampling    | Same strategy as Juliet (balanced TP/FP)    | Low                              |
| Confidence calibration charts  | Validate High/Medium/Low confidence signals | Low                              |
| Youden Index + MCC scoring     | Match OWASP scorecard + SastBench paper     | Low                              |
| PrimeVul adapter               | Cleaner C/C++ labels vs DiverseVul          | Low                              |
| SastBench REST `/analyze` harness | Submit to SastBench leaderboard          | Medium                           |

### Web-language coverage (Java + Python via OWASP Benchmark)

VulnHunterX targets memory-safety in C/C++ today and the existing adapters reflect that. To exercise the web-side rule packs (CodeQL `java-queries`, `python-queries`, Semgrep web rules), we add the **OWASP Benchmark Project** suites:

- `BenchmarkJava` v1.2 — ~2,740 cases, 11 CWE categories (SQLi, XSS, path traversal, command injection, LDAP, XPath, weak random, weak hash, trust boundary, insecure cookie, crypto). GPL-2.0.
- `BenchmarkPython` v0.1 — ~1,230 cases over the same taxonomy. GPL-3.0.

Both ship a CSV manifest (`expectedresults-<version>.csv`) keyed by `BenchmarkTest#####` filename + CWE — adapter parsing is straightforward. Datasets are cloned into `benchmarks/datasets/` at runtime; **VulnHunterX project code remains MIT**, the GPL applies only to the cloned test corpora (not vendored, not linked).

OWASP's official scorecard uses the **Youden Index** (TPR + TNR − 1, ×100). We currently report P/R/F1 + FP-reduction; Youden Index is queued for the follow-up scoring upgrade so reviewers know which metrics are pending.

---

## References

- [LLM4FPM](https://arxiv.org/abs/2411.03079) — Juliet C/C++ multi-turn LLM FP mitigation (Nov 2024)
- [SecLLMHolmes](https://arxiv.org/abs/2312.12575) — Hand-crafted 228-scenario LLM vulnerability benchmark (IEEE S&P 2024)
- [CASTLE](https://arxiv.org/abs/2503.09433) — 250-program micro-benchmark for SAST + LLM (TASE 2025)
- [ZeroFalse](https://arxiv.org/abs/2510.02534) — Zero-shot LLM FP reduction on OWASP Benchmark (Oct 2025)
- [CISC](https://aclanthology.org/2025.findings-acl.1030.pdf) — Self-consistency with confidence for LLM code review (ACL 2025)
- [LLMxCPG](https://arxiv.org/abs/2507.16585) — Code Property Graph-guided LLM slicing (USENIX Security 2025)
- [Sifting the Noise](https://arxiv.org/abs/2601.22952) — Comparative study of LLM agents for SAST FP filtering
- [D2A Quality Study](https://rolandcroft.github.io/assets/publications/ICSE_23.pdf) — Dataset quality analysis (ICSE 2023)
- [Java Juliet Subset](https://arxiv.org/abs/2405.15614) — Balanced subset sampling for LLM evaluation (May 2024)
- [DiverseVul](https://github.com/wagner-group/diversevul) — 349K C/C++ functions with CVE-backed labels (RAID 2023)
- [OWASP Benchmark Project](https://owasp.org/www-project-benchmark/) — synthetic SAST test suites with CSV ground truth ([Java repo](https://github.com/OWASP-Benchmark/BenchmarkJava), [Python repo](https://github.com/OWASP-Benchmark/BenchmarkPython))
- [Juliet C/C++ 1.3.1](https://samate.nist.gov/SARD/test-suites/116) — NIST SARD test suite
