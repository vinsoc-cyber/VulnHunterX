# VulnHunterX Training — "Self-Scan Your Code"

A complete developer lesson on using VulnHunterX to scan your own source: a
**120-minute presentation** (64 slides, dark theme), a **30-minute hands-on workshop** on a
vulnerable C++ repo, and a **20-question quiz**. Scope is static analysis + LLM
verification (pipeline Stages 1–4); fuzzing (Stages 5–8) is intentionally excluded.

> This is a teaching set, distinct from the product-intro deck in
> [`../presentation/`](../presentation/). It builds the fundamentals (SAST/DAST,
> CodeQL/Semgrep internals, AST + control/data flow, LLM pros/cons) before the
> VulnHunterX-specific material.

## Files

| File | Purpose |
|---|---|
| [LESSON.md](LESSON.md) | The 120-min talk, slide-by-slide (64 slides), with speaker notes. Source of truth for the deck. |
| [generate_lesson_deck.py](generate_lesson_deck.py) | Builds `VulnHunterX-120min.pptx` with `python-pptx` — **dark theme**, diagram-driven (flowcharts, AST tree, taint diagram, comparison panels, 17 tables). Rule/question counts are computed from `config/` at build time so the deck never drifts. |
| `VulnHunterX-120min.pptx` | The generated slide deck (regenerate any time). |
| [WORKSHOP-cpp.md](WORKSHOP-cpp.md) | Copy-paste hands-on: Ollama Cloud setup + scan of `insecure-coding-examples`, plus homework on `dvcp` — each with a ground-truth answer key. |
| [QUIZ.md](QUIZ.md) | 20 multiple-choice questions + answer key. |

## Regenerate the deck

```bash
pip install python-pptx          # one-off; not a runtime dependency of VulnHunterX
python docs/training/generate_lesson_deck.py
```

This rewrites `VulnHunterX-120min.pptx` and prints the rule counts it read from
`config/`. **Speaker notes** are attached to every content slide (the 120-minute
talk track). Open the result in PowerPoint, LibreOffice Impress, or Google Slides.

## Structure (7 parts, ~120 min + 30-min workshop)

| Part | Section | Minutes |
|---|---|---|
| 0 | Title + agenda | 3 |
| 1 | Source-code scanning: SAST & DAST | 12 |
| 2 | How CodeQL & Semgrep scan | 24 |
| 3 | AST, control flow & data flow (CodeQL vs tree-sitter) | 22 |
| 4 | LLM vulnerability verification — pros & cons | 14 |
| 5 | VulnHunterX architecture & stages (no fuzzing) | 30 |
| 6 | How to use it: CLI + a worked example | 10 |
| 7 | Results & limitations + benchmarks | 16 |
| — | **Hands-on workshop** (`WORKSHOP-cpp.md`) | 30 |

## Ground truth

The workshop and homework answer keys are derived from
[`../benchmarks/ground-truth-baselines.md`](../benchmarks/ground-truth-baselines.md)
(workshop = §3 `insecure-coding-examples`, homework = §2 `dvcp`). Both repos were
chosen for **reliable builds** so CodeQL tracing never fails during the exercise.

## Why counts are computed, not hardcoded

Like the 60-min deck, `generate_lesson_deck.py` globs
`config/codeql-custom/**/*.ql`, counts `- id:` lines in
`config/semgrep-custom/*.yaml`, and counts top-level keys in
`config/prompts/*questions*.yaml`. Re-running always reflects the current repo.
