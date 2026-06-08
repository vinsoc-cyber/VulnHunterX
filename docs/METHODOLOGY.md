# Methodology — Why Guided-Question Triage Works

A two-page primer on the idea behind VulnHunterX. For the full treatment see
[paper/vulnhunterx_paper.md](paper/vulnhunterx_paper.md) and
[benchmarks/RESEARCH.md](../benchmarks/RESEARCH.md).

## The problem: SAST over-approximates on purpose

Static analysis tools (CodeQL, Semgrep, OpenGrep) are built to flag *every* program point that
*might* be vulnerable. They deliberately err toward over-reporting — a missed bug is worse than a
spurious one. The consequence is well known: **false-positive rates of 30–80%**. The dominant
cost of running SAST in production is therefore not analysis time, it's the **human triage** of a
mountain of findings, most of which are safe.

That triage is exactly the kind of bounded, evidence-based reasoning an LLM should be able to do.

## Why "just ask an LLM if it's a bug" fails

Hand a model a code snippet and the raw question "is this a vulnerability?" and it pattern-matches:
it sees `free(p)` followed by `*p` and says "use-after-free" without checking whether the paths
actually overlap, whether there's a guard, or whether the pointer was reassigned. The
SecLLMHolmes study (IEEE S&P 2024) measured frontier LLMs capping around ~40% accuracy on
hand-crafted security scenarios for precisely this reason — confident pattern-matching, no code
evidence.

## The Vulnhalla idea: imitate the analyst, not the pattern

VulnHunterX implements the **Vulnhalla** methodology
([CyberArk](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)):
frame triage as *expert imitation*. A senior analyst doesn't guess — they ask a specific sequence
of questions and read the code to answer each one. The verdict is the **last** thing they decide,
downstream of the evidence. VulnHunterX makes the LLM do the same, through four mechanisms.

### 1. Rule-specific guided questions

Each rule class has a bank of evidence-bound questions
([config/prompts/*_questions.yaml](../config/prompts/), 348 templates across 6 languages plus a
generic fallback). A question must:

- **(P1) bind to evidence** — answerable only by citing concrete artifacts (line numbers,
  function names), not vibes;
- **(P2) be atomic** — one sub-fact per question; compound questions are split;
- **(P3) admit refusal** — "Not visible in the provided context" is a valid answer, which is what
  triggers context expansion (below).

Example, for Python SQL injection: *"Quote the EXACT sink statement and name the variable passed
to it. List every assignment to that variable on each path that reaches the sink, with line
numbers. For each, determine whether the value derives from user input or a constant/safe
source."* This forces step-by-step code reading instead of pattern-matching.

### 2. Answer-before-verdict

The response schema requires the model to emit its **answers and a data-flow trace first**, and
only then the `verdict` field. Because the model generates left-to-right, conditioning the verdict
token on already-written, citation-bearing answers ties the conclusion to evidence rather than to
a snap judgment. A post-processor downgrades any High/Medium verdict whose reasoning is pure
pattern-language with no `file:line` citations.

### 3. Multi-turn context broker

When the model answers "not visible here," it requests more context from a **fixed vocabulary** —
`caller:`, `function:`, `struct:`, `global:`, `macro:`, `callees:`, `free_sites:`, `destructor:`,
`field_writes:`, and a handful more. The engine resolves these from pre-extracted CSVs (or a
tree-sitter fallback), appends them, and re-prompts. Crucially this **never re-runs the SAST
engine** — context lookups are cheap — so multi-turn refinement costs a few extra LLM tokens, not
another full analysis. See [context-extraction-flow.md](context-extraction-flow.md).

### 4. Stay-honest guards

Critical CWE classes (access-control, taint on web frameworks) are forced to a minimum of 2
turns. High-confidence single-turn FP verdicts get a second-opinion re-audit (single-turn FPs were
the dominant error mode in early benchmarks). Confidence is downgraded when evidence is thin.

## Does it work?

Yes, and the most interesting result is that **reasoning structure beats model size**. On public
benchmarks a $0, locally-runnable model with this protocol matches or beats GPT-4.1-mini and GPT-5:

| Dataset | raw-SAST precision | VulnHunterX precision | FP-reduction |
|---|---|---|---|
| OWASP-Python | 37.7% | 87.3% | 91.4% |
| OWASP-Java | 90.0% | 97.7% | 80.0% |
| Juliet C/C++ | 50.0% | 83.8% | 82.2% |
| SecLLMHolmes | 52.3% | 82.1% | 79.4% |

(Best model per row; see [Results](../README.md#results) and the
[benchmark comparison files](../benchmarks/results/) for full numbers, models, and costs.)

Ablations show the **biggest single jump is raw-SAST → any multi-turn LLM** (~20 F1 points), with
guided questions adding the hard-case tail (~3–5 points of recall). Confidence is calibrated —
high-confidence verdicts are measurably more accurate — so the score works as a triage filter.

## What it does *not* do

It is a triage layer, not an oracle. It can be blind to facts outside the provided snippet+context
(e.g. weak-hash findings judged from a snippet), struggles on inherently context-heavy classes
like XXE, and is batch-speed, not real-time. See the honest-limits discussion in
[INTERPRETING_RESULTS.md](INTERPRETING_RESULTS.md) and the talk's "Limits" section.
