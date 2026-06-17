# VulnHunterX — workshop presentation

A developer-facing workshop deck in four parts: what VulnHunterX is (features,
architecture, methodology, benchmark results), how to install and use it, a real
worked example on dvpwa, and take-home homework on dvcp — each with a baseline
answer key so attendees can self-verify their scan results.

## Files

| File | Purpose |
|---|---|
| `generate_deck.py` | Builds the `.pptx` with `python-pptx`. Rule/coverage counts are computed at build time from `config/` so the deck never drifts. |
| `VulnHunterX-60min.pptx` | The generated slide deck (regenerate any time). |
| `WORKSHOP.md` | Copy-paste handout for attendees (setup, exercises, homework, cheat sheet). |

## Regenerate the deck

```bash
pip install python-pptx          # one-off; not a runtime dependency of VulnHunterX
python docs/presentation/generate_deck.py
```

This rewrites `VulnHunterX-60min.pptx` and prints the rule counts it read from
`config/`. Open the result in PowerPoint, LibreOffice Impress, or Google Slides.
**Speaker notes** are attached to every slide (the 60-minute talk track).

## Structure (4 parts, ~60 min)

| Part | Section | Slides | Time |
|---|---|---|---|
| — | Opening + agenda | 1–2 | 3 min |
| 1 | VulnHunterX introduction — features, architecture, methodology, results | 3–17 | 22 min |
| 2 | How to install & use | 18–22 | 10 min |
| 3 | Real example — dvpwa (with baseline answer key) | 23–26 | 12 min |
| 4 | Homework — dvcp (with baseline answer key) | 27–30 | 8 min |

Part 1 includes 3 benchmark **result** slides (sourced from `benchmarks/results/`) and
the guided-question methodology slides. Parts 3 and 4 each end with a **baseline answer
key** — the known true positives and false-positive traps — so attendees can score their
own runs (dvpwa key from the realvuln ground truth; dvcp key from the upstream `imgRead.c`).

## Why counts are computed, not hardcoded

The repo's `README.md` summary table has drifted from the actual rule files.
`generate_deck.py` instead globs `config/codeql-custom/**/*.ql`, counts `- id:`
lines in `config/semgrep-custom/*.yaml`, and counts top-level keys in
`config/prompts/*questions*.yaml`. Re-running the script always reflects the
current state of the repo.
