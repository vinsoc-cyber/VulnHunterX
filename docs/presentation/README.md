# VulnHunterX — 60-minute presentation

A developer-facing workshop deck on what VulnHunterX is, how it works, how to
install the toolchain (including on Windows), plus hands-on exercises and
homework.

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

## Timing budget (~60 min)

| Section | Slides | Time |
|---|---|---|
| Opening + agenda | 1–2 | 3 min |
| The problem | 3–4 | 5 min |
| What VulnHunterX is | 5–8 | 5 min |
| How it works | 9–14 | 12 min |
| Toolchain & install | 15–18 | 10 min |
| Windows support | 19–21 | 5 min |
| Workshop / live demo | 22–24 | 10 min |
| Exercises | 25–26 | 5 min |
| Homework + wrap-up | 27–28 | 5 min |

## Why counts are computed, not hardcoded

The repo's `README.md` summary table has drifted from the actual rule files.
`generate_deck.py` instead globs `config/codeql-custom/**/*.ql`, counts `- id:`
lines in `config/semgrep-custom/*.yaml`, and counts top-level keys in
`config/prompts/*questions*.yaml`. Re-running the script always reflects the
current state of the repo.
