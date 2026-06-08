# HK Hack 2026 Talk — 40-Minute Run-of-Show

**Venue/format:** Hong Kong HACK 2026 (https://www.hk-hack.com/) main track / Demo Labs,
40-minute slot, technical security audience.
**Deliverable:** slide-by-slide outline with speaker notes, timing budget, and a demo engineering
checklist.

> **Built deck:** [`hk-hack-vulnhunterx.pptx`](hk-hack-vulnhunterx.pptx) (33 slides, presenter-style,
> full speaker notes in each slide's notes pane — includes the paper's stages 1–4 pipeline diagram,
> a second worked example (C/C++ use-after-free, CWE-416), and a `context_extractor.py` graph). It
> is generated from this outline by
> [`build_slides.py`](build_slides.py) — edit the script and re-run `python docs/talk/build_slides.py`
> (needs `python-pptx`) to regenerate. Open the `.pptx` in PowerPoint / Keynote / Google Slides.

All numbers below are quoted from real run files under
[../../benchmarks/results/](../../benchmarks/results/) — keep them in sync with
[the README Results section](../../README.md#results).

---

## Title & thesis

**Working title:** *"Picking True Bugs from the CodeQL Haystack: Teaching Small LLMs to Triage
Like a Senior Analyst."*

**Thesis (say it twice — slide 1 and slide 18):** SAST's real cost is human triage, not analysis
time. Structured, evidence-anchored LLM reasoning — *not* a bigger model — moves the cost/accuracy
frontier: a **$0, locally-runnable model deletes ~90% of false positives while keeping >95% of
real bugs.**

**Narrative arc:** provocation → why the obvious fix fails → the method → the evidence → live
demo → honest limits & red-team → extensibility → takeaway.

## Time budget (40 min)

| Block | Slides | Minutes |
|---|---|---|
| Hook & problem | 1–4 | 7 |
| Method | 5–8 | 8 |
| Evidence | 9–11 | 7 |
| Live demo | 12–14 | 9 |
| Limits & red-team | 15–16 | 5 |
| Extensibility & takeaways | 17–18 | 3 |
| Buffer / transitions | — | 1 |

Leave room-policy Q&A for after the slot (or use slide 19 backups if time remains).

---

## Slide-by-slide

### 1 — Title / hook · 1.5 min
**On screen:** title, your name/handle, repo URL/QR, one number: *"30–80% of SAST findings are
false positives."*
**Say:** Security teams don't drown in *missed* bugs — they drown in *triaging* the ones the
scanner flagged, most of which are safe. "What if a model that costs zero dollars could do the
first pass — and do it well?" Name-check the lineage: this builds on CyberArk's *Vulnhalla*
methodology. Establish credibility up front.

### 2 — Why this is an HK Hack problem · 1.5 min
**On screen:** the triage funnel — thousands of findings → analyst hours → a few real bugs; the
rest ignored.
**Say:** FP fatigue is a security failure mode: when 70% of alerts are noise, analysts start
ignoring the queue, and the real bug rides in with the noise. Dual-use framing: this is defender
tooling *and* an offense recon accelerator (triage attacker-relevant findings fast).

### 3 — When the scanner is wrong: two real false positives · 2 min
**On screen:** two FPs taken verbatim from committed verdict JSONs (model `qwen3-coder-480b`, $0):
- **vorbis** `cpp/alloca-in-loop` @ `lib/vorbisfile.c:2396` (CWE-770) — *FP, High (0.90), 2 iters.*
  `alloca()` in a loop, but the iteration count (`ch1`, channels) and size (`n1`, block size) are
  bounded by the Vorbis format spec → no stack exhaustion.
- **libjpeg-turbo** `cpp/world-writable-file-creation` @ `tjexample.c:320` (CWE-732) — *FP, Medium
  (0.75), 4 iters.* The flagged line is a `tjTransform()` call on memory buffers — there is no
  `0666` file creation here; the rule **mis-attributed** the location.
**Say:** Two distinct ways SAST is "wrong": a *true* rule defeated by a domain constraint, and a
rule firing on the *wrong line*. Both killed with a cited reason, on a $0 model — the exact judgment
we're automating. (Sources in "Source files" below.)

### 4 — Why "just ask GPT if it's a bug" fails · 2 min
**On screen:** naive prompt → confident wrong answer; the SecLLMHolmes ~40% ceiling.
**Say:** Free-form prompting pattern-matches: `free(p)` then `*p` → "use-after-free!" with no check
that the paths overlap or a guard exists. SecLLMHolmes (IEEE S&P 2024) measured frontier models
capping ~40% on hand-crafted scenarios for this reason. The gap isn't model IQ — it's *method*.

### 5 — The pipeline in one diagram · 2 min
**On screen:** 8 stages; group 1–4 (prepare → analyze → verify → report) vs 5–8 (fuzz confirm).
**Say:** SARIF is the spine. Stages 1–2 are ordinary SAST; stage 3 is the LLM verification this
talk is about; stages 5–8 optionally *prove* a bug with a crash. Everything routes through one
SARIF contract — remember that for the extensibility slide.

### 6 — Guided questions = encoded analyst expertise · 2 min
**On screen:** two real banks, quoted verbatim from `config/prompts/`:
- `py/sql-injection` (taint) — 6 questions incl. *"Quote the EXACT sink statement…"*, *"List EVERY
  assignment… and the LAST one"*, *"What specific defense sanitises the value? … Vague
  'sanitisation' is not acceptable"*, and the explicit *"if you cannot point to the tainted value
  reaching the sink AND the absence of every defense → verdict False Positive."* `min_iterations: 2`.
- `cpp/use-after-free` (lifetime) — 10 questions incl. *ANCHOR/CLASSIFY the flagged line*, *enumerate
  every free site (request `free_sites:<ptr>`)*, *shortest free→use path*, and the **DECISION RULE**:
  *"mark FP ONLY with POSITIVE evidence of a defense; pattern-only reasoning is NOT enough → prefer
  Needs-More-Data."* `min_iterations: 3`.
**Say:** Instead of "is this a bug?", we ask the *same ordered questions a senior reviewer asks*.
Three rules behind how each is written: **evidence-binding** (cite line numbers), **atomicity** (one
fact per question), **refusal-admissibility** ("not visible here" → fetch more context). The *why*,
from the file's own header: the model must answer **ALL** questions **before** the verdict — forcing
step-by-step reasoning instead of pattern-matching. `min_iterations` is calibrated per CWE class
(taint CWEs on framework langs: OWASP-Python 1-iter 57.1% → 2-iter 95.8%).

### 7 — Answer-before-verdict · 2 min
**On screen:** the JSON schema — `answers[]` and `data_flow` come *before* `verdict`.
**Say:** This is the core trick. The model must write its cited answers and the data-flow trace
*first*; the verdict token is generated last, conditioned on that evidence. A post-processor
downgrades any verdict whose reasoning is pure pattern-language with no `file:line` citation.
Autoregression becomes our friend instead of our enemy.

### 8 — Context broker + multi-turn · 2 min
**On screen:** the fixed request vocabulary (`caller:`, `struct:`, `free_sites:`, …) and a 2-turn
exchange.
**Say:** When the model needs more, it asks from a *fixed vocabulary*; we resolve it from
pre-extracted CSVs (or a tree-sitter fallback) and re-prompt — **we never re-run the SAST
engine**, so multi-turn costs tokens, not another analysis. In practice the **mean conversation is
2.74 turns** and only **0.8% of findings ever hit a forced decision** (OWASP-Python, 366 entries).

### 9 — Evidence: the headline · 2.5 min
**On screen:** the flagship table.

| Dataset | raw-SAST P / F1 | VulnHunterX P / F1 | FP-reduction |
|---|---|---|---|
| OWASP-Python (300) | 37.7% / 54.7% | **87.3% / 92.4%** | **91.4%** |
| OWASP-Java (full) | 90.0% / 94.7% | **97.7% / 96.6%** | **80.0%** |
| Juliet C/C++ (full) | 50.0% / 66.7% | **83.8% / 88.5%** | **82.2%** |
| SecLLMHolmes (228) | 52.3% / 68.7% | **82.1% / 84.7%** | **79.4%** |

**Say:** Precision roughly doubles; we delete ~80–91% of false positives while keeping >90% of
real bugs. Every cell is from a published run file — point at the repo. (Best model per row.)

### 10 — Small beats big, cheap beats expensive · 2.5 min
**On screen:** model matrix on OWASP-Python.

| Model | F1 | Cost / 300 findings |
|---|---|---|
| DeepSeek-v4-flash ($0 pass-through) | **92.4%** | ~$0.40 |
| gpt-4.1-mini | 89.4% | ~$1.10 |
| Qwen3-Coder (local) | 78.7% | $0 |
| GPT-5 (SecLLMHolmes) | 82.0% | ~$16.75 / 228 |

**Say:** The $0 model *wins*. GPT-5 costs ~$17 for 228 findings and doesn't lead. The lever is the
protocol, not the parameter count. Mention latency honestly: this is batch-speed (tens of seconds
per finding), not inline-on-keystroke.

### 11 — Ablation honesty · 2 min
**On screen:** raw-SAST → zero-shot → generic-Q → guided-Q bars.
**Say:** Don't oversell. The *biggest* jump is raw-SAST → any multi-turn LLM (~20 F1 points).
Zero-shot is surprisingly strong; guided questions add the hard-case tail (~3–5 points of recall),
and on *synthetic* Juliet generic questions even edge out specific ones. Telling the audience where
your method *doesn't* dominate is what earns the room's trust.

### 12 — Live demo setup · 1 min
**On screen:** two terminals — a benign real-world lib and a deliberately vulnerable app (mirrors
`examples/pipeline_python.py`).
**Say:** State the success criteria out loud: the vulnerable app's real bug survives as a TP; a
benign lib's scary-looking finding (like the real FPs on slide 3) gets killed as an FP — both with
cited reasoning.

### 13 — Live demo run · 6 min
**Do:** run `verify` on a handful of pre-staged findings. Show, in order:
1. a benign finding being **killed** as an FP with a cited reason (like the slide-3 cases);
2. a real bug **surviving** as a TP with a data-flow trace;
3. a live **multi-turn context request** (`caller:`/`struct:`) and the revised verdict;
4. the **confidence downgrade** catching a thin, pattern-matched verdict.
**Backup (REHEARSE THIS):** pre-recorded screencast + cached verdict JSON. Network/LLM flakiness on
a conference floor is a *when*, not an *if*.

### 14 — Demo payoff: fuzz confirmation · 2 min
**On screen (pre-recorded):** for a C/C++ TP, stages 5–8 generate a libFuzzer harness → ASan crash
→ triaged crashing input.
**Say:** This closes the loop: from "the LLM says use-after-free" to "here is the input that
crashes it." That's the difference between a triage opinion and a filed, reproducible bug. (Fuzz
live on stage is slow — use the recording.)

### 15 — Limits & failure modes · 2.5 min
**On screen:** the honest list.
**Say:** Snippet-blind spots (weak-hash findings judged from a snippet → low recall on that class);
inherently context-heavy classes like XXE are hard; NMD when context is missing; batch latency, not
real-time; and prompt-injection risk — the analyzed code is untrusted input to the model. Candor
here is a feature for this audience.

### 16 — Red-team the tool itself · 2 min
**On screen:** a crafted snippet with a comment trying to talk the model out of a real verdict.
**Say:** Can an attacker poison triage? Yes, in principle. Mitigations: evidence-binding (a verdict
must cite real `file:line`, not prose), the confidence downgrade for unsupported reasoning, and a
second-opinion re-audit on suspicious high-confidence FPs. Invite the room to break it — that's the
research frontier.

### 17 — Extensibility · 1.5 min
**On screen:** "SARIF is the only contract" — 59 custom CodeQL queries + 89 custom Semgrep rules,
CWE→question routing, `audit_rule_coverage.py` as a CI gate.
**Say:** Bring your own rules, engine, or language. New rules tag a CWE and route through the same
verification core; an audit script fails CI if a rule isn't wired to a question. No core changes.

### 18 — Takeaways + CTA · 1.5 min
**On screen:** three lines + repo QR.
**Say:** (1) Reasoning *structure* beats model *size*. (2) FP-reduction is the ROI metric security
teams actually feel. (3) It's open source (MIT) with a full benchmark harness — reproduce every
number on this slide. Invite contributions; restate the thesis.

### 19 — Backup / appendix (Q&A only)
- **Inside the conversation — two real multi-turn traces** (a *matched pair*, both `deepseek-v4-flash`, $0):
  - **Trace #1 → False Positive:** `go/log-injection` @ `merchant_be.go:92`. T1: answer 6 Qs →
    *Needs More Data* (Low 0.30), request `callees:MaskMerchantKey/MaskSensitive/extractContextFields`
    → engine returns `"[No callees found]"` → T2: **False Positive (High 0.95)** — input is logged
    only as structured `zap.String` fields, which the encoder escapes, so injection can't forge entries.
  - **Trace #2 → True Positive:** `go/clear-text-logging` @ `logger.go:46`. SAME mechanism — request
    `callees:extractContextFields` → identical `"[No callees found]"` — but T2: **True Positive
    (Medium 0.65)**: header data reaches the logger unsanitized and no defense can be confirmed.
  - **Punchline:** identical context outcome, opposite verdicts — the decision tracks the reasoning
    about a *visible defense*, not a pattern.
- Per-CWE breakdown tables · token/cost math · architecture deep-dive (context-extraction flow) ·
  exact `run_model_matrix.py` reproduction commands · confidence-calibration plots.

---

## Demo engineering checklist

- [ ] Pre-clone both targets; pre-build CodeQL DBs; cache SARIF + a curated set of verdict JSONs.
- [ ] Hand-pick demo findings so the FP-kill, TP-survive, multi-turn, and downgrade moments each
      have a clean example.
- [ ] Record the **full** screencast as a fallback and rehearse switching to it seamlessly.
- [ ] Use a **local/DeepSeek** model on stage — no live API rate-limit or cost surprises.
- [ ] Pre-render the fuzz crash: save the crashing input + ASan trace as static artifacts.
- [ ] Rehearse the **offline path** — registry Semgrep packs need network; run `--profile full`.
- [ ] Time the live block twice; if it runs long, slide 14 (fuzz) is the safe cut.
- [ ] Have the repo URL on every slide footer (people screenshot mid-talk).

## Source files for every number (keep honest)

| Claim | Source |
|---|---|
| OWASP-Python P/F1/FP-reduction, model matrix | [`matrix_20260604_151302/COMPARISON.md`](../../benchmarks/results/matrix_20260604_151302/COMPARISON.md) |
| Juliet C/C++ | [`matrix_20260605_114348/COMPARISON.md`](../../benchmarks/results/matrix_20260605_114348/COMPARISON.md) |
| SecLLMHolmes (incl. GPT-5 cost) | [`matrix_20260531_180948/COMPARISON.md`](../../benchmarks/results/matrix_20260531_180948/COMPARISON.md) |
| OWASP-Java 97.7%/96.6%/80% | [`20260519_022324/REPORT.md`](../../benchmarks/results/20260519_022324/REPORT.md) |
| Mean 2.74 turns, 0.8% forced | `20260519_141614/summary.json` |
| Rule/question/CWE counts | [`config/RULES.md`](../../config/RULES.md) + live config files |
| Guided-question banks (slides 6, 7, 8) | [`config/prompts/python_questions.yaml`](../../config/prompts/python_questions.yaml) (`py/sql-injection`) · [`config/prompts/cpp_questions.yaml`](../../config/prompts/cpp_questions.yaml) (`cpp/use-after-free`) |
| FP case — vorbis (slide 3) | `output/c/vorbis/verification_results/cpp_alloca-in-loop_2396.json` |
| FP case — libjpeg-turbo (slide 3) | `output/c/libjpeg-turbo/verification_results/cpp_world-writable-file-creation_320.json` |
| Trace #1 — log-injection FP (slide 32) | `output/go/1216-services/verification_results/go_log-injection_92.json` |
| Trace #2 — clear-text-logging TP (slide 33) | `output/go/1216-services/verification_results/go_clear-text-logging_46.json` |
