# Fuzzing removal: implementation and migration

The removal plan was implemented on 4 October 2026. VulnHunterX supports
`prepare → analyze → verify → report` for C, C++, Python, JavaScript, PHP,
Java, Go, and C#. `scan` composes these stages; `interactive` and its `wizard`
alias dispatch a scan. Unsupported stages 5–8 have been removed.

This document records the completed cleanup and migration policy. Names of
removed interfaces below identify breaking changes, not supported operations.
The changes are recorded under **Unreleased** in [CHANGELOG.md](../CHANGELOG.md).

## Completed implementation

| Area | Delivered change |
| --- | --- |
| [CLI parser](../src/vuln_hunter_x/cli/main.py) and [handlers](../src/vuln_hunter_x/cli/commands.py) | Removed imports, registrations, argument helpers, handlers, and dispatch for `build-sanitized`, `extract-fuzz-context`, `generate-fuzz-drivers`, and `fuzz-run` |
| Python package | Deleted all 11 modules under `src/vuln_hunter_x/fuzz/`, including exports, harness generation, compilation repair, execution, corpus handling, and crash triage |
| [Configuration](../src/vuln_hunter_x/core/config.py) | Removed `FuzzConfig`, `Config.fuzz`, construction and argument merging; removed `RepoPaths.sanitized_build`, `.fuzz_targets`, and `.fuzz_results` |
| [Constants](../src/vuln_hunter_x/core/constants.py) | Removed `DEFAULT_MAX_FIX_ITERATIONS`, `TIMEOUT_SANITIZED_BUILD`, `BUILD_LOG_LLM_PREVIEW_CHARS`, and `BUILD_LOG_MAX_ERROR_CHARS`; retained `TIMEOUT_LLM_REQUEST` |
| C++ queries | Deleted only `config/queries/tools/cpp/function_signatures.ql` and `includes.ql`, which had no remaining consumers |
| [Examples](../examples/README.md) | Removed optional functions, invocations, flags, statistics, timeouts, and output hints from the C, C++, zlib, and batch scripts; refreshed target and stage descriptions |
| Tests | Removed five dedicated fuzz/crash modules and the obsolete fuzz-repair test from the shared completion-helper module; added [supported-pipeline regressions](../tests/test_supported_pipeline.py) |
| Documentation | Current guides, configuration examples, issue components, workshops, and regenerated decks describe the four supported stages; agent instructions now reflect completed removal |

The example dry-run check also exposed an existing out-of-scope `args` reference
in the batch runner. Verification's `max_iterations` is now passed explicitly
from the parser through `run_pipeline()` to `stage_verify()` and regression-tested.

## Migration policy

This is a breaking removal of the four commands and the Python APIs listed
above. Removed commands fail with argparse's invalid-command error (exit code 2)
and list the remaining choices. There are no compatibility imports or command
aliases for fuzzing. Update automation to use the supported static pipeline.

For one transition release, an old YAML file containing `fuzz:` still loads:
the entire section is ignored and a warning asks the operator to remove it.
Its values are neither parsed nor logged. `MAX_FIX_ITERATIONS` is also ignored
with a warning on presence, including an empty value. Remove that environment
setting; it controls no remaining behavior. These warnings are transitional;
a later release can remove the special diagnostics. Unrelated unknown YAML
keys retain their existing handling.

The four affected examples reject obsolete `--fuzz`, `--fuzz-timeout`, and
`--fuzz-max-time` options before starting work, including options supplied with
`=`. Supported options such as `--dry-run`, `--skip-clone`, and `--api` remain
available where previously provided.

Consumers importing `vuln_hunter_x.fuzz` or constructing the removed configuration
fields must remove those calls. Install into a clean environment when checking
migration so stale files from earlier installations cannot mask package removal.

## Preserved behavior and data

- CodeQL database preparation, normal target build commands and LLM build
  assistance, source-only Semgrep/OpenGrep fallback, local-path mode, and all
  eight language choices remain supported.
- CodeQL/tree-sitter/snippet context, `ContextExtractorDB`, database discovery,
  query execution, and `QUERIES_BY_LANG` remain. Ordinary functions, callers,
  structs, globals, macros, free-site, destructor, and field-write queries and
  CSVs remain. `enums.ql` and `typedefs.ql` remain because typed evidence consumes
  them; their ordinary extraction coverage is unchanged.
- Input sanitizer/guard evidence, source-to-sink validation, guided questions,
  deterministic policies, provider routing, and repository-scoped source lookup
  remain. Detection of test, benchmark, and fuzz harness files in scanned
  projects remains, as do fuzzgoat targets and historical benchmark references.
- Finding identity, anchors, TP/FP/NMD semantics, saved verdicts, opt-in raw
  responses, and English/Vietnamese reports remain. These verdicts are
  static/LLM judgments; they do not constitute executed exploit confirmation.
- Provider dependencies, tree-sitter bindings, YAML support, and benchmark
  extras remain. `pyproject.toml` had no dedicated fuzz dependency or extra.
- Existing `output/`, `repos/`, crash/corpus artifacts, benchmark baselines, and
  historical changelog entries were not deleted or migrated.

## Validation record

Checks used Python 3.12 in an isolated development environment, with synthetic
targets and mocked providers for pipeline and report checks. No live provider
or precision/recall benchmark run was required.

- Before removal, the available main suite passed **1,810 tests**. The normal
  `python -m pytest tests/` command cannot collect
  `tests/test_recall_1192_services.py` because the ignored fixture
  `benchmarks/results/test_proj/1192/ground-truth.json` is absent. The same
  collection failure occurs after removal. The broader comparison excludes
  only that module; its source and fixture handling are unchanged.
- After removal, the available main suite passed **1,702 tests**. Comparing test
  identities confirmed that all **1,657** retained baseline tests still pass;
  **153** obsolete tests were removed and **45** new regressions passed. The
  subsequently added batch-runner regression passed in the final focused run:
  **192 tests** covering pipeline composition, configuration, local paths, the
  wizard, saved verdicts, context, and reporting, including all **46** new tests.
- The separate `benchmark/tests/` suite passed **58 tests** before and after.
- Mocked saved verdicts (including opt-in raw responses) and English/Vietnamese
  reports match the pre-removal revision byte for byte using fixed timestamps
  and a deterministic translation stub.
- C, C++, zlib, and synthetic batch example dry-runs pass. Removed-option
  rejection and verification-option forwarding pass regression checks.
- Wheel and sdist builds pass. Both archives contain verification and reporting
  and omit the fuzz package. A clean wheel install passes remaining command
  help checks, rejects the four removed commands with exit code 2, and cannot
  import `vuln_hunter_x.fuzz`.
- Required Ruff, formatting, and MyPy checks still report baseline issues:
  **31 lint findings** remain; **28 source files** would reformat (31 before);
  **30 type errors in 8 files** remain (49 in 11 files before). Comparison by
  file and diagnostic found no new lint/type errors or newly unformatted files.
  The new regression module passes Ruff and formatting checks.

## Release and rollback

Publish these removals as breaking changes with the migration policy above.
External Python consumers have not been inventoried, so their migration needs
remain a release consideration. The changes do not establish speed gains or
unchanged real-world precision/recall; ordinary scans already omitted fuzzing.

Rollback by reverting the removal commit or pinning the previous release.
Stored artifacts can be inspected with that version. Deleting old artifacts
requires a separate, explicitly scoped request.
