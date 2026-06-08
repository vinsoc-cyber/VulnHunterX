# VulnHunterX — arXiv submission package

Contents:

```
arxiv/
├── vulnhunterx.tex      # Main LaTeX source (article class, ~1650 lines)
├── vulnhunterx.pdf      # Reference compile (22 pages, generated 2026-05-25)
├── figures/
│   ├── architecture.pdf # Figure 1 — framework architecture
│   ├── pipeline.pdf     # Figure 2 — end-to-end pipeline (stages 1–4)
│   └── verification.pdf # Figure 3 — per-finding LLM verification flow
└── README.md            # This file
```

## Compile locally

The source compiles with a standard TeX Live `medium` profile or larger.
The reference PDF in this directory was produced by:

```bash
docker run --rm -v "$(pwd)":/data -w /data \
    texlive/texlive:latest-medium pdflatex vulnhunterx.tex
# (Run twice for cross-references; arXiv does this automatically.)
docker run --rm -v "$(pwd)":/data -w /data \
    texlive/texlive:latest-medium pdflatex vulnhunterx.tex
```

Or, with a native LaTeX install:

```bash
pdflatex vulnhunterx.tex && pdflatex vulnhunterx.tex
```

Required packages (all in TeX Live medium): `inputenc`, `fontenc`,
`lmodern`, `geometry`, `microtype`, `amsmath`, `amssymb`, `graphicx`,
`xcolor`, `booktabs`, `array`, `longtable`, `tabularx`, `enumitem`,
`listings`, `textcomp`, `url`, `hyperref`.

## Upload to arXiv

1. **Sanity-check the PDF.** Open `vulnhunterx.pdf` in this directory
   and verify the 22-page output matches expectations (title page,
   abstract, 10 sections, 3 figures embedded, 3-column threats-to-
   validity table in Appendix C, bibliography).

2. **Build the submission tarball.** arXiv accepts a `.tar.gz` of the
   LaTeX source plus figures (no compiled PDF needed; arXiv re-compiles
   on their farm).

   ```bash
   cd docs/paper/arxiv
   tar czf vulnhunterx-arxiv.tar.gz vulnhunterx.tex figures/
   ```

3. **Submit at <https://arxiv.org/submit>.**
   - Primary category: `cs.CR` (Cryptography and Security).
   - Cross-listings to consider: `cs.SE` (Software Engineering),
     `cs.LG` (Machine Learning) — at the author's discretion.
   - License: MIT for the artifact; choose `arXiv non-exclusive license
     to distribute` for the preprint.

4. **Title and abstract for the arXiv form** are duplicated from the
   `.tex` file's `\title{}` and `abstract` environment. Keywords:
   *static analysis, false positive reduction, large language models,
   guided questions, multi-turn verification, CodeQL, Semgrep, custom
   rules, developer extensibility, secure software engineering*.

## Provenance

- **Markdown source:** [../vulnhunterx_paper.md](../vulnhunterx_paper.md)
- **Mermaid sources for figures:** [../diagrams.md](../diagrams.md)
- **Figure regeneration:** if you edit `../diagrams.md`, re-render with

  ```bash
  cd figures
  npx --yes -p @mermaid-js/mermaid-cli mmdc \
      -i ../../diagrams.md -o diag.pdf --pdfFit
  mv diag-1.pdf architecture.pdf
  mv diag-2.pdf pipeline.pdf
  mv diag-3.pdf verification.pdf
  ```

## Notes for the companion empirical paper

This preprint is positioned as a **methodological contribution**. The
empirical evaluation on Juliet C/C++, OWASP Benchmark (Java), and
CASTLE — including model-size sweeps, schema-reordering ablations, and
generic-vs-specialised-question ablations — will be reported in a
companion paper. The arXiv abstract and §§ 1, 7, 8, 10 of this
manuscript reference that companion paper as forthcoming.
