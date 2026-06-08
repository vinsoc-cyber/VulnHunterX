# Interpreting Results

How to read what VulnHunterX produces: the per-finding verdicts, the markdown report, and the
benchmark metrics.

## The three verdicts

Every finding gets one of:

| Verdict | Meaning | What to do |
|---|---|---|
| **True Positive (TP)** | The LLM found evidence the vulnerability is real and reachable. | Fix it. For C/C++, optionally confirm with a crash (see [FUZZING.md](FUZZING.md)). |
| **False Positive (FP)** | The LLM found evidence the finding is safe (guard present, input not attacker-controlled, sink benign). | Suppress / ignore — but sample-check, especially low-confidence FPs. |
| **Needs More Data (NMD)** | The LLM couldn't answer a required question from the available context, even after multi-turn expansion. | Treat as "unresolved." Provide more context (broader scan, CodeQL backend) or review manually. |

NMD is a feature, not a failure: the model declining to guess is what keeps precision honest.

## Confidence

Each verdict carries a `confidence` (High / Medium / Low) and a numeric `confidence_score`.
Confidence is **calibrated** — across benchmarks, high-confidence verdicts are measurably more
accurate than low-confidence ones — so you can use it as a triage filter: act on High-confidence
TPs first; manually review Low-confidence verdicts and NMDs.

The engine deliberately **downgrades** confidence when a verdict isn't backed by concrete
`file:line` citations, and re-audits some High-confidence single-turn FPs with a second opinion.
So a Low-confidence verdict often means "the evidence was thin," not "the model was unsure for no
reason."

## The verdict JSON

Each finding writes one JSON file under `output/<lang>/<repo>/verification_results/`. Key fields:

- `verdict`, `confidence`, `confidence_score`
- `answers` — the model's answer to each guided question (the evidence trail)
- `data_flow` — the traced source → … → sink path
- `reasoning` — 1–2 sentence summary
- `iterations` — how many turns it took
- `context_needed` — any context the model still wanted at the end

When a verdict surprises you, read `answers` and `data_flow` first — they show exactly which fact
drove the decision. To see the full LLM conversation, run `verify --log-file <path>` (see
[FAQ.md](FAQ.md)).

## The markdown report

`verify` writes `report.md` (and `report_vi.md`). Sections:

- **Executive summary** — TP/FP/NMD counts and the before/after picture.
- **Findings overview** — raw SAST count vs. post-verification.
- **Severity breakdown** and **CWE distribution**.
- **Per-finding detail** — verdict, confidence, reasoning, data flow.

Regenerate or relocate it with `vuln-hunter-x report` (see the [README CLI reference](../README.md#report)).

## Benchmark metrics — precision vs. FP-reduction vs. effective-recall

The benchmark tables (see [Results](../README.md#results) and
[benchmarks/README.md](../benchmarks/README.md)) use several metrics that are easy to confuse:

| Metric | Definition | Reads as |
|---|---|---|
| **Precision** | TP / (TP + FP) among findings the tool *called* TP | "When it says bug, how often is it right?" |
| **Recall** | TP found / all real bugs | "Of the real bugs, how many survived triage?" |
| **F1** | harmonic mean of precision & recall | single headline number |
| **FP-reduction** | fraction of raw-SAST false positives the LLM removed | "How much triage noise did it delete?" |
| **Effective-recall** | recall counting NMDs on real bugs as misses | honest recall — doesn't hide indecision |
| **TP-preservation** | fraction of raw-SAST true positives kept | "Did we throw away real bugs?" |
| **NMD rate** | fraction of findings left unresolved | how often it declined to decide |

Why both precision and FP-reduction? Precision tells you the quality of the surviving TP set;
FP-reduction tells you how much manual triage you saved. A tool can have modest precision but huge
FP-reduction (it deleted most noise but the dataset was noisy to begin with) — OWASP-Python is
exactly this case: precision 37.7% → 87.3% **because** 91.4% of FPs were removed.

Watch **effective-recall** and **TP-preservation** to make sure FP-reduction wasn't bought by
discarding real bugs. Across the production runs, TP-preservation stays in the ~90–96% range.

## Cost and latency

The benchmark `summary.json` / `COMPARISON.md` files report tokens/finding (~4K–12K), p95 latency
(seconds, batch-friendly — not real-time), and real provider cost. Local Ollama and pass-through
models report `$0`. Use these to budget a scan: ~10K tokens × number of findings × your model's
price. See [LLM_PROVIDERS.md](LLM_PROVIDERS.md) for per-provider cost guidance.
