# benchmark/

Pluggable VHX benchmark framework. First mode: `versionab` (verifier version A/B).

## Run (from the repo root)

    python benchmark/src/benchmark.py versionab                       # all targets, auto-compare to latest
    python benchmark/src/benchmark.py versionab --targets dvcp        # subset
    python benchmark/src/benchmark.py versionab --previous 1.0.0@a2951e9
    python benchmark/src/benchmark.py versionab --config deepseek-deepseek-v4-flash-temp0-iter5  # pick a config
    python benchmark/src/benchmark.py --dry-run versionab             # preview, $0
    python benchmark/src/benchmark.py versionab --compare-only --previous 1.0.0@a2951e9  # free re-compare

Backend/run knobs live in flat per-config files under `config/`, named for their
result-affecting knobs `<provider>-<model>-temp<t>-iter<n>.yaml` (default
`openai-gpt-5.5-temp0-iter5`; select another with `--config <name>`). Targets live in `test_case/`.
Scored baselines are committed under `result/version_ab/<version>@<sha>/`; raw output is
kept (gitignored) under `output/`. See `docs/superpowers/specs/2026-06-30-benchmark-version-ab-design.md`.
