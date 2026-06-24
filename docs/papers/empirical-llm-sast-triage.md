# Paper Proposal & Full Draft Outline

> **Type:** Empirical study (measurement paper)
> **Working title:** *What Actually Reduces False Positives? An Empirical Study of
> LLM-Assisted Static-Analysis Triage Across Models, Languages, CWEs, and Cost*
> **Primary venue:** USENIX Security (Security/measurement track). **Alternates:** IEEE S&P,
> ACM CCS. ~13 pages + appendix; artifact-evaluation eligible.
> **Status of this document:** living outline. Each claim is tagged
> **[E]** = evidence already in repo, **[P]** = partial/needs a confirming run,
> **[N]** = needs a new experiment.

---

## 0. One-paragraph pitch

LLM-assisted triage of static-analysis findings is everywhere in 2025–26, but it is evaluated
ad hoc: a single model, a single dataset, one prompting style, no cost accounting, and FP
reduction reported without measuring the recall it silently destroys. We run a controlled,
multi-factor study — **5 LLMs × 4 triage strategies × 6 ground-truth datasets × 8 languages** —
to isolate *which* techniques actually reduce false positives, *for which vulnerability classes*,
*at what recall cost*, and *at what dollar cost*. We find the dominant factor is the **model**,
not the prompt; that structured guided-question prompting helps most on **taint-style CWEs in
framework languages** and is near-neutral on synthetic memory-safety code; that **multi-turn
depth has sharply diminishing, CWE-dependent returns**; and that cheap deterministic
**post-hoc calibration** recovers most of the over-confidence error without extra LLM calls. We
also show a **dynamic fuzzing oracle** can independently confirm a subset of verdicts, giving
label-free ground truth on C/C++.

---

## 1. Framing & why it's distinct

Prior work either (a) builds *one* technique and reports it favorably (LLM4FPM, ZeroFalse), or
(b) tests *base models* in isolation and concludes they are unreliable (SecLLMHolmes, CASTLE).
Nobody has run the **controlled ablation across the technique design space and the model axis at
once**, with honest recall-cost and dollar-cost accounting. That gap is the paper.

The VulnHunterX system is the *instrument*, not the contribution — the contribution is the
**findings and the methodology to obtain them**. This keeps the paper a measurement study
(USENIX's sweet spot) rather than a tool paper, and keeps it complementary to the in-repo
**RealVuln benchmark paper** (`benchmarks/datasets/realvuln/paper/`), which contributes the
*dataset*; here RealVuln is simply one of six datasets.

---

## 2. Contributions (framed as findings)

1. **A controlled multi-factor study** of LLM SAST triage: 5 models × 4 strategies × 6 datasets,
   with precision/recall/F1/F2, FP-reduction, TP-preservation, NMD rate, per-confidence
   calibration, latency, and real provider cost — all reported jointly. **[E/P]**
2. **The model dominates the prompt.** On Juliet C/C++, switching model moves FP-reduction from
   ~24% (gpt-4.1-mini) to ~82–87% (deepseek) at the *same* strategy and ~⅖ the cost; switching
   strategy moves it far less. **[E]**
3. **Guided questions are not universally better** — they pay off on framework taint CWEs
   (path-traversal, SQLi, SSRF, mass-assignment) and are roughly neutral on synthetic
   memory-safety code, which we explain mechanistically. **[E/P]**
4. **Iteration depth has CWE- and language-dependent returns**, justifying a *gated* depth policy
   rather than a flat "more turns is better." **[P]**
5. **Deterministic post-hoc calibration** recovers most over-confidence error at zero extra LLM
   cost, and **self-consistency voting** buys accuracy only past a cost threshold most teams
   won't pay. **[E/N]**
6. **A dynamic fuzzing oracle** (ASan/UBSan + LLM-repaired harnesses) independently confirms a
   subset of C/C++ verdicts — label-free ground truth and a cross-check on LLM TP claims. **[N]**

---

## 3. Research questions (the spine)

| RQ | Question | Backing artifact | Status |
|----|----------|------------------|--------|
| RQ1 | How much does LLM triage cut SAST FPs, and what recall does it cost? | `matrix_*/COMPARISON.md`, per-approach `summary.json` (raw-sast vs vulnhunterx) | **[E]** |
| RQ2 | Do rule/CWE-specific guided questions beat generic few-shot and zero-shot? | `ablation-generic` / `ablation-zero` / `vulnhunterx` in `matrix_*` | **[E/P]** |
| RQ3 | When does multi-turn depth help, by CWE × language? | `iteration_sweep:[1,2,3]` (`benchmarks/config/benchmark.yaml`), `min_iterations` table `questions/loader.py:47-79` | **[P]** |
| RQ4 | Can cheap deterministic calibration fix over-confidence? | calibrators `verification/engine.py:352-571`; per-confidence buckets already in `summary.json` | **[E/N]** |
| RQ5 | Do repo-level signals + cross-tool consensus change verdicts? | `context/repo_signals.py`, reconciliation `engine.py:226-349` | **[N]** |
| RQ6 | Self-consistency voting: accuracy vs samples vs $? | `analyze_with_voting` `llm/client.py:729-850`; cost fields in `summary.json` | **[N]** |
| RQ7 | How often does dynamic fuzz confirmation agree with LLM TP verdicts (C/C++)? | `fuzz/` (Stages 5–8), dvcp / Juliet | **[N]** |
| RQ-X | Cost & the NMD state: $/finding, p95 latency, and effective recall | cost/latency/`nmd_rate` fields across all runs | **[E]** |

Every RQ below names the figure/table it carries and the file that backs it.

---

## 4. Section-by-section draft with claims

### §1 Introduction
- **Claim:** SAST is precision-poor by construction (sound over-approximation); LLM triage is the
  emerging fix but is evaluated without controlling for model, dataset, strategy, or cost.
- **Claim:** FP reduction reported alone is misleading — recall cost must be co-reported.
- **Figure 1:** teaser — FP-reduction vs recall-preservation scatter, one point per
  (model, strategy), showing the spread is dominated by model. Backing: `matrix_*` summaries. **[E]**

### §2 Background & threat model
- SAST taxonomy (CodeQL data-flow, Semgrep/OpenGrep pattern), why FPs arise.
- The **central tension**: a triager that nukes FPs by also dropping TPs is worse than useless;
  we adopt **F2** (recall-weighted, β=2) and **TP-preservation rate** as first-class metrics
  (F2 formula reusable from `benchmarks/datasets/realvuln/paper/sections/benchmark-design.tex`).
- Define the **NEEDS_MORE_DATA (NMD)** verdict and **effective recall** =
  TP-confirmed / (TP-confirmed + TP-missed + NMDs-that-were-TPs).

### §3 Study design
- **Models (5+):** deepseek, gpt-4.1-mini, gpt-5, glm5.1, qwen3-coder:480b-cloud — already run in
  `matrix_20260531_180948`, `…0601`, `…0604`, `…0605`. **[E]**
- **Strategies (4):** `raw-sast` (no LLM baseline), `ablation-zero` (zero-shot), `ablation-generic`
  (generic few-shot questions), `vulnhunterx` (rule/CWE-specific guided + multi-turn + signals).
- **Datasets (6):** OpenVuln/ZeroFalse (58 real Java CodeQL alerts, TP/FP-labeled), SecLLMHolmes
  (~228 scenarios, 8 CWEs), Juliet C/C++ (stratified per-CWE sample), OWASP BenchmarkJava (~2.7k),
  OWASP BenchmarkPython (~1.2k), RealVuln (796 real Python web findings, 120 FP-traps). Inventory
  table from `docs/benchmarks/ground-truth-baselines.md` + `benchmarks/RESEARCH.md §Datasets`.
- **Engines (3):** CodeQL, Semgrep, OpenGrep.
- **Metrics:** precision, recall, F1, F2, Youden's J, FP-reduction (+95% CI), TP-preservation,
  NMD rate, per-confidence calibration accuracy, tokens/finding, p95 latency, USD/finding — all
  emitted by the harness today (`summary.json` schema). **[E]**
- **Reproducibility:** resumable checkpointed runs, three-layer JSONL logging, fixed per-CWE
  stratified sampling, `run_config.json` per run. **[E]**
- **Table 1:** the full design matrix (models × strategies × datasets) with which cells are run.

### §4 RQ1 — Baseline effect: how much, at what recall cost
- **Claim [E]:** Raw SAST on Juliet sits at precision 50.0% / recall 100% / F1 66.7%
  (model-independent baseline, `matrix_20260605_114348/COMPARISON.md`). LLM triage lifts precision
  to **56.8% (gpt-4.1-mini)** up to **83.8% (deepseek)** under the same `vulnhunterx` strategy.
- **Claim [E]:** Recall cost is real and model-dependent — deepseek `vulnhunterx` trades recall
  down to 93.8% to reach 82.2% FP-reduction, while gpt-4.1-mini keeps recall 100% but only
  removes 23.9% of FPs. **There is no free lunch and the operating point is a model choice.**
- **Table 2:** per-(model, dataset, strategy) leaderboard (P/R/F1/F2/FP-red/NMD/$/p95).
- **Finding sentence:** "FP-reduction varied 3.4× across models at fixed strategy and fixed
  dataset — the largest single factor in the study."

### §5 RQ2 — Prompt structure: guided vs generic vs zero-shot
- **Claim [E/P]:** On Juliet (synthetic C/C++), `vulnhunterx` ≈ `ablation-generic` for the strong
  model (deepseek: 83.8% vs 88.1% precision) — **guided questions do not help, and can slightly
  hurt, on synthetic memory-safety code**. This is an honest, counter-intuitive result.
- **Claim [P]:** On **framework-language taint datasets** (OWASP Python, RealVuln), guided
  questions are expected to dominate — the owasp-python design comment records
  CWE-22/643 accuracy 57.1% → 95.8% once the rule-specific flow questions + 2-iteration gate
  engage (`questions/loader.py`). *Needs the matched cross-strategy run on these datasets.*
- **Mechanism:** guided questions force enumeration of every assignment to the sink variable and
  naming of a *specific* defense — high value where exploitability hinges on a sanitizer/guard
  (taint), low value where the bug is a local pattern (UAF/overflow).
- **Figure 2:** strategy delta (Δ precision, Δ recall) per dataset, grouped by CWE family
  (taint vs memory-safety vs access-control).

### §6 RQ3 — Iteration depth × CWE × language
- **Claim [P]:** Marginal accuracy per additional context round is steep for the first turn on
  taint CWEs in framework languages, flat-to-negative for memory-safety/pattern CWEs in C/C++ —
  motivating a **gated** depth policy (`min_iterations` override: 2 for access-control all langs;
  2 for taint CWEs only on Python/JS/Java/PHP/Go/C#; 1 elsewhere).
- **Backing:** `iteration_sweep:[1,2,3]` is built into the harness
  (`benchmarks/config/benchmark.yaml`); `mean_iterations`/`max_iterations` already in summaries.
  *Needs the sweep re-run split by CWE family to draw the curve.*
- **Figure 3:** accuracy vs iteration count, one line per CWE family, faceted by language.
- **Finding sentence:** "Beyond the gated depth, additional turns added cost without accuracy —
  the marginal token spend bought nothing for C/C++ pattern classes."

### §7 RQ4 — Post-hoc calibration of over-confidence
- **Claim [E]:** Base models are mis-calibrated — e.g. gpt-4.1-mini ablation-generic on Juliet:
  High-confidence bucket only 63.6% correct, Low bucket 50.6% (per-confidence buckets in
  `summary.json.calibration`). High confidence ≠ high accuracy.
- **Claim [N]:** Four cheap deterministic calibrators (`engine.py:352-571`) — pattern-language
  downgrade, local-prototype-pollution downgrade, CLI path-injection downgrade, rule-scope-drift
  downgrade — recover most of the over-confidence error **at zero extra LLM cost**. Measure
  calibration-error (ECE) and verdict accuracy with calibrators on vs off.
- **Figure 4:** reliability diagram (confidence vs empirical accuracy) before/after calibration.
- **Table 3:** ECE and bucketed accuracy, calibrators on/off, per model.

### §8 RQ5 — Repo-level signals & cross-tool consensus
- **Claim [N]:** Framework detection (`repo_signals.py`) prevents the model from reasoning about
  the wrong framework's defenses (the dvpwa aiohttp-vs-Django case); commented-out-symbol signals
  correct reachability reasoning on disabled middleware. Measure verdict-flip rate and
  accuracy-delta with signals on/off on RealVuln + dvpwa.
- **Claim [N]:** Asymmetric cross-tool reconciliation (`engine.py:226-349`) — *never drop a TP*;
  a corroborated FP becomes NMD — reduces single-tool false negatives. Measure on findings where
  CodeQL/Semgrep/OpenGrep disagree at the same location.
- **Table 4:** signal/consensus ablation (flip rate, ΔF2, ΔTP-preservation).

### §9 RQ6 — Self-consistency economics
- **Claim [N]:** Confidence-weighted voting (`analyze_with_voting`, CISC-style) improves accuracy
  with samples ∈ {1,3,5}, but the accuracy/$ curve flattens fast; we report the break-even where
  a stronger single model beats N samples of a weaker one. (Cost already tracked per run.)
- **Figure 5:** accuracy vs USD/finding scatter; voting samples and model choice on one plane.

### §10 RQ7 — Dynamic fuzzing as an independent oracle
- **Claim [N]:** For C/C++ findings, the fuzz subsystem (sanitized build → type-aware harness →
  LLM repair loop → crash triage with stack-hash dedup, `fuzz/`) can **independently confirm** a
  subset of LLM TP verdicts via real ASan/UBSan crashes — label-free ground truth.
- **Claim [N]:** Report agreement rate (LLM-TP ∧ fuzz-crash), and the harness-generation success
  rate (how often the LLM repair loop produces a compiling, reaching harness) as a feasibility
  bound on this oracle.
- **Table 5:** fuzz-confirmation outcomes on dvcp + Juliet subset.

### §11 Discussion — generalizable lessons
- Model choice is the highest-leverage decision; prompt engineering is second-order.
- Guided questions are a *targeted* tool (taint CWEs / framework langs), not a default win.
- Depth and voting are cost multipliers with narrow ROI — gate them.
- Calibration is the cheapest accuracy you can buy; ship it.
- When is LLM triage worth it? A decision rule keyed to FP-reduction × $/finding × recall floor.

### §12 Threats to validity
- Label noise (DiverseVul ~60% accuracy → excluded from labeled tracks; rationale in RESEARCH.md).
- Synthetic vs real (Juliet/OWASP synthetic; RealVuln/dvpwa real — we report both and contrast).
- Pretraining leakage of public benchmarks → why real-repo datasets (RealVuln, OpenVuln) matter.
- Model/version drift (pin model IDs + dates; runs stamped in `run_config.json`).
- Tool coupling — findings are mediated by VulnHunterX's prompts; we mitigate by including the
  zero-shot arm (strategy-independent) and multiple models.

### §13 Related work
- Position vs LLM4FPM, ZeroFalse, SecLLMHolmes, CASTLE, CISC, LLMxCPG, "Sifting the Noise."
- **Table 6:** comparison axes (real vs synthetic data, # models, ablations, recall-cost reported,
  $ reported, dynamic confirmation) — draft already in `benchmarks/RESEARCH.md §1`.

### §14 Ethics & artifact availability
- Only intentionally-vulnerable or already-public CVE-backed targets; no zero-day disclosure.
- Artifact: benchmark harness + RealVuln dataset + all `summary.json`/`COMPARISON.md` +
  figure-generation scripts → artifact-evaluation badge target.
  (Ethics/data-availability prose reusable from `benchmarks/datasets/realvuln/paper/sections/`.)

---

## 5. Evidence inventory (what exists today)

| Asset | Path | Use |
|---|---|---|
| Model matrix (5 models × 4 strategies × Juliet) | `benchmarks/results/matrix_2026053*–0605*/` | RQ1, RQ2, RQ4, cost |
| Per-model comparison tables | `benchmarks/results/matrix_*/COMPARISON.md` | Tables 2, 6 |
| OWASP Java / Python runs | `benchmarks/results/20260519_022324/`, `…073728/` | RQ2 (framework langs) |
| Juliet C/C++ vulnhunterx run | `benchmarks/results/20260529_084004/` | RQ1, RQ3 |
| Calibration buckets per run | `summary.json.calibration` | RQ4, Fig 4 |
| Cost/latency per run | `summary.json` (`total_cost_usd`, `p95_latency_s`, `tokens_per_finding`) | RQ-X, Fig 5 |
| Iteration sweep harness | `benchmarks/config/benchmark.yaml` (`iteration_sweep`) | RQ3 |
| Calibrators / signals / voting / fuzz code | `verification/engine.py`, `context/repo_signals.py`, `llm/client.py`, `fuzz/` | RQ4–7 |
| Literature review + dataset rationale | `benchmarks/RESEARCH.md` | §13, §3 |
| Ground-truth inventory | `docs/benchmarks/ground-truth-baselines.md` | §3 Table 1 |
| Reusable LaTeX prose (F2, ethics, data-availability) | `benchmarks/datasets/realvuln/paper/sections/` | §2, §14 |

---

## 6. Gap analysis — experiments to run before submission

Mapped to the existing `benchmarks/run_benchmark.py` harness. Each item turns a **[P]/[N]** claim
into **[E]**. Silent caps (sampling, per-CWE limits) must be logged in the run config.

1. **Cross-strategy on framework datasets [P→E]** — run all 4 strategies × ≥3 models on OWASP
   Python, OWASP Java, RealVuln (currently only partial single-model runs exist). Backs RQ2/§5.
2. **Iteration sweep by CWE family [P→E]** — `--iteration-sweep` on a taint-heavy and a
   memory-safety dataset; bucket by CWE family. Backs RQ3/Fig 3.
3. **Calibration on/off ablation [N→E]** — re-score existing matrix runs with calibrators
   disabled vs enabled; compute ECE + reliability diagram. Backs RQ4/Fig 4/Table 3.
4. **Signals & consensus ablation [N→E]** — RealVuln + dvpwa with `repo_signals` and cross-tool
   reconciliation toggled. Backs RQ5/Table 4.
5. **Voting sweep [N→E]** — `samples ∈ {1,3,5}` on two models, log $/finding. Backs RQ6/Fig 5.
6. **Fuzz-confirmation runs [N→E]** — Stages 5–8 on dvcp + Juliet C/C++ subset; record harness
   build-success and crash-agreement rates. Backs RQ7/Table 5.
7. **Figure/table generation [N→E]** — extend the matrix `COMPARISON.md` generator to emit the
   six figures (teaser scatter, strategy-delta, iteration curve, reliability diagram, cost
   scatter, fuzz table). A `generate_figures.py` template exists in the RealVuln paper plan.

**Honesty rule:** until item N lands, the corresponding section stays tagged **[P]/[N]** in the
draft. No claim is presented as evidenced before its run exists under `benchmarks/results/`.

---

## 7. Suggested timeline (≈10 weeks to a submittable draft)

| Wk | Milestone |
|----|-----------|
| 1–2 | Lock model/dataset matrix; complete cross-strategy framework-dataset runs (gap #1) |
| 3 | Iteration sweep + calibration ablation (gaps #2, #3) |
| 4 | Signals/consensus + voting sweeps (gaps #4, #5) |
| 5 | Fuzz-confirmation runs (gap #6) |
| 6 | Figure/table generation pipeline (gap #7); freeze numbers |
| 7–8 | Write §§1–10 from this outline |
| 9 | §§11–14, related-work table, threats; internal review |
| 10 | Artifact packaging + camera polish; submit |

---

## 8. Verification of this proposal document

1. **Render:** valid GitHub markdown (tables/headings) — confirmed structure.
2. **Traceability:** every **[E]** number above is drawn from a real file under
   `benchmarks/results/` (Juliet baseline 50/100/66.7 and the deepseek/gpt-4.1-mini rows are from
   `matrix_20260605_114348/COMPARISON.md`).
3. **Self-consistency:** each RQ has a matching results section (§4–§10) and a gap-analysis entry
   (§6); status tags are consistent (no claim is both [E] and [N]).
4. **Optional:** `python scripts/audit_rule_coverage.py` to refresh rule/CWE coverage counts cited
   in §3 before the camera-ready.
