# CI/CD Integration

VulnHunterX runs headless, so it drops into CI as a verification gate: run SAST, let the LLM
triage, and fail the build (or post a report) on high-confidence true positives. Because the LLM
stage suppresses most false positives, the gate is far less noisy than raw SAST.

## What you need in CI

- Python 3.12+ and the package (`pip install -e .`).
- CodeQL CLI (and Semgrep/OpenGrep if you use them).
- An LLM provider key as a CI secret. For zero marginal cost, point at a local/self-hosted Ollama
  runner; otherwise use an API key (see [LLM_PROVIDERS.md](LLM_PROVIDERS.md)).

Keep cost bounded with `--limit`, `--category`, and a cheaper model on PRs.

## GitHub Actions

```yaml
name: vulnhunterx
on: [pull_request]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }

      - name: Install VulnHunterX
        run: pip install -e ".[dev]"

      - name: Install CodeQL CLI
        uses: github/codeql-action/setup@v3   # or download the CLI manually

      - name: Run pipeline
        env:
          LLM_PROVIDER: openai
          LLM_MODEL: gpt-4o-mini
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          vuln-hunter-x prepare  --local-path . --lang python --name app
          vuln-hunter-x analyze  --local-path . --lang python --name app --profile full
          vuln-hunter-x verify   --local-path . --lang python --name app --limit 50
          vuln-hunter-x report   --repo app --lang python

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnhunterx-report
          path: output/python/app/verification_results/report.md
```

To **fail the build** on confirmed high-confidence bugs, add a small step that scans the verdict
JSON files (under `output/<lang>/<repo>/verification_results/`) for `verdict == "True Positive"`
with `confidence == "High"` and exits non-zero. Parse with `jq` or a one-line Python script — the
schema is documented in [INTERPRETING_RESULTS.md](INTERPRETING_RESULTS.md).

## GitLab CI

```yaml
vulnhunterx:
  image: python:3.12
  variables:
    LLM_PROVIDER: openai
    LLM_MODEL: gpt-4o-mini
  script:
    - pip install -e ".[dev]"
    # install CodeQL CLI into PATH here
    - vuln-hunter-x prepare --local-path . --lang python --name app
    - vuln-hunter-x analyze --local-path . --lang python --name app --profile full
    - vuln-hunter-x verify  --local-path . --lang python --name app --limit 50
    - vuln-hunter-x report  --repo app --lang python
  artifacts:
    when: always
    paths:
      - output/python/app/verification_results/report.md
```

Set `OPENAI_API_KEY` (or the provider key you use) as a masked CI variable.

## Gate the *rules*, not just the findings

In a separate, fast job, verify that every custom rule is wired to a guided question — this
catches misconfigured rules before they silently fall back to generic triage:

```bash
python scripts/audit_rule_coverage.py --fail-on-gaps
```

It exits non-zero when a rule or CWE has no guided-question route, and writes a coverage matrix to
`output/audit/`. See [RULE_PROFILES.md](RULE_PROFILES.md).

## Tips

- **Speed/cost on PRs:** `--profile standard`, a small model, and `--limit` keep PR runs cheap;
  run `--profile full` on a nightly schedule.
- **Cache the CodeQL DB** between runs when the source is unchanged to skip stage 1.
- **Latency:** verification is batch-speed (seconds per finding); budget accordingly and run it
  asynchronously rather than blocking on it inline where possible.
