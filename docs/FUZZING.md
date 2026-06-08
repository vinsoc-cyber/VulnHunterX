# Fuzzing — Dynamic Confirmation (Stages 5–8)

Static + LLM triage tells you a finding is *probably* a true positive. Fuzzing closes the loop: it
generates a harness, runs it under sanitizers, and either produces a **crashing input** (definitive
proof) or doesn't. These stages live in [src/vuln_hunter_x/fuzz/](../src/vuln_hunter_x/fuzz/) and
are most mature for C/C++ (libFuzzer + ASan/UBSan), with harness templates for Python, Java,
JavaScript, and PHP as well.

## When to use it

- You have **verified true positives** in a memory-unsafe language (C/C++) and want crash-backed
  proof before filing or fixing.
- You want to convert "the LLM says use-after-free" into "here is the input that triggers it."

It is optional — stages 1–4 are a complete triage pipeline on their own.

## The four stages

| Stage | Command | Does |
|---|---|---|
| 5 | `build-sanitized` | Rebuilds the target with ASan/UBSan and records a build manifest (symbols, link deps). |
| 6 | `extract-fuzz-context` | Extracts function signatures and includes (from the CodeQL DB) so harnesses can call targets with correct types. |
| 7 | `generate-fuzz-drivers` | Generates harnesses for prioritized targets; `--build` compiles them; `--llm-fix` runs an LLM repair loop when compilation fails. |
| 8 | `fuzz-run` | Runs the harnesses under libFuzzer, collects crashes, and (`--triage`) parses ASan output and deduplicates by stack hash. |

```bash
vuln-hunter-x build-sanitized       --repo libucl
vuln-hunter-x extract-fuzz-context  --repo libucl
vuln-hunter-x generate-fuzz-drivers --repo libucl --build --llm-fix
vuln-hunter-x fuzz-run              --repo libucl --triage
```

The C/C++ example scripts accept `--fuzz` to run these end-to-end (e.g.
`python examples/pipeline_c.py --fuzz`).

## How harnesses are generated

Target selection prioritizes **verified TP findings** and maps each to its enclosing function.
Generation is type-aware: enums become `PickValueInArray` over real constants, typedefs are
resolved to their underlying type, buffer+size pairs are correlated, `FILE*` is backed by
`fmemopen` with fuzzed content, char arrays consume bytes as strings. For static functions, a
source-inclusion trick (`#include "file.c"` with `#define main`) makes them linkable. When a
generated harness doesn't compile, the LLM fix loop proposes missing includes/casts and retries.

## Other languages

Harness generation templates exist for:

| Language | Engine | Dependency |
|---|---|---|
| C/C++ | libFuzzer | clang ≥ 12 |
| Python | Atheris | `pip install atheris` |
| Java | Jazzer | `jazzer` binary on `PATH` |
| JavaScript | Jazzer.js | `npm install @jazzer.js/core` |
| PHP | php-fuzzer | `composer require nikic/php-fuzzer` |

## Reading crash results

`fuzz-run --triage` writes `output/<lang>/<repo>/fuzz_results/summary.json` plus crash artifacts.
Each unique crash records its type (heap-buffer-overflow, use-after-free, segfault, …), the
crashing input, and a deduplicated stack signature. A crash that maps back to a verified TP is the
strongest possible confirmation; treat it as release-blocking.

## Troubleshooting

See the fuzz section of [TROUBLESHOOTING.md](TROUBLESHOOTING.md#stages-58--fuzz-cc-and-other-languages)
— sanitizer build failures, harness compilation, and "no crashes found" (often a true negative or
a target that needs longer fuzzing / a seed corpus).
