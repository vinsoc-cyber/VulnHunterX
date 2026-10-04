# VulnHunterX code standards

Use the settings in [pyproject.toml](../pyproject.toml) and the workflow in [CONTRIBUTING.md](../CONTRIBUTING.md). This document explains how those settings apply to the scan and verification pipeline.

## Python and tooling

- Support Python `>=3.12,<3.14`. Ruff and MyPy target Python 3.12.
- Ruff formats with a 100-character line length and double quotes; enabled lint families are `E`, `F`, `I`, `UP`, `B`, and `SIM`, with `E501` ignored.
- Use UTF-8, LF line endings, a final newline, and `from __future__ import annotations` in new modules.
- Add useful annotations to public interfaces and validate dynamic scanner/provider payloads at adapters. Reuse `Finding`, `Verdict`, configuration dataclasses, and typed evidence rather than inventing parallel representations.
- Preserve existing licensing headers. Resolving inconsistent historical license labels is a separate task.

## Module responsibilities

CLI parsing belongs in `cli/main.py`; stage orchestration belongs in `cli/commands.py`. Reuse stage functions for `scan` rather than implementing another pipeline.

Scanner-specific work belongs in `codeql/`, `semgrep/`, or `opengrep/`; normalized findings pass through `sarif/` and `core/types.py`. Source and context retrieval belong in `context/`, preserving repository scope and the CodeQL, tree-sitter, and snippet paths.

Prompt and provider work belongs in `questions/` and `llm/`. Verification policies belong in `verification/policy/`; reporting belongs in `reporting/`. Keep shared completion and validation helpers available to every remaining caller when deleting a feature.

Use `core/constants.py` for shared defaults. When changing a configuration field, update its declaration, YAML parsing, environment override, CLI override, and `Config.merge_with_args()` together. Reuse the current interfaces rather than introducing unrelated architectural layers.

## I/O and errors

- Bound new network and subprocess operations with timeouts and a justified retry policy. Respect the surrounding synchronous or threaded design; an async rewrite is not a prerequisite for ordinary changes.
- Preserve cancellation and provider retry semantics. Do not swallow expected execution failures or convert them into successful results.
- Catch specific errors where practical. Broad boundary catches need safe diagnostics and an explicit failed or translated outcome.
- Use module logging for library diagnostics. CLI and example scripts already use `print()` for user output; retain that distinction.
- Prefer small functions with one responsibility and composition over unnecessary inheritance. Avoid broad refactors alongside a focused bug fix.

## Tests and benchmarks

Main tests live under `tests/`. The separate version comparison harness has tests under `benchmark/tests/`, which must be selected explicitly. Default pytest options generate coverage under `output/`; there is no configured minimum percentage.

Use temporary paths, synthetic source, and mocked providers/subprocesses for meaningful behavior tests. Preserve regressions for source anchors, repository isolation, context parity, verdict serialization, and policy evidence. Do not add live provider calls to default tests.

Keep benchmark entry populations, scanner anchors, grading definitions, and committed historical scores intact. Real benchmark comparisons can depend on model calls and installed analyzers; a mocked regression run does not establish unchanged real-world precision or recall.

## Validation commands

Run commands from the repository root in an environment with the `dev` dependencies installed:

```bash
python -m ruff check src/
python -m ruff format --check src/
python -m mypy src/
python -m pytest tests/
python -m pytest benchmark/tests/   # when the comparison harness is affected
```

For a focused run without coverage output, use `python -m pytest -o addopts='' tests/test_repo_paths.py`. Check documentation links and examples for documentation-only work. Report existing failures and unavailable tools separately from failures introduced by the change; do not weaken checks or claim unexecuted commands passed.
