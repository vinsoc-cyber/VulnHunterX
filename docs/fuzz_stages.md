# Fuzz-Based Vulnerability Confirmation (Stages 5–8)

Optional pipeline stages to confirm CodeQL/LLM findings by building with sanitizers and generating fuzz drivers. **C/C++ only.**

## Stage 5: Build with sanitizers

Builds the repository with AddressSanitizer and UBSan in a **separate** directory so the CodeQL database build is untouched. Output is a manifest used to link fuzz harnesses.

### Sub-stages

- **5.1 Prepare build env**: Sets `CC=clang`, `CXX=clang++`, `CFLAGS`/`CXXFLAGS`/`LDFLAGS` with sanitizer flags. Build command comes from `sanitized_build_command` or `build_command` in `config/repos.yaml`.
- **5.2 Run sanitized build**: Copies repo to `output/<lang>/<repo>/sanitized_build/src` and runs the build there (out-of-tree dir `build_sanitized` used when applicable).
- **5.3 Write manifest**: Writes `output/<lang>/<repo>/sanitized_build/manifest.json` with `libs`, `objects`, `include_dirs`, and `source_root`.

### CLI

```bash
vuln-hunter-x build-sanitized --repo <name>   # Build one repo
vuln-hunter-x build-sanitized --lang cpp      # All C++ repos
vuln-hunter-x build-sanitized --repo libucl -f  # Force rebuild
vuln-hunter-x build-sanitized --dry-run       # Preview
```

### Config

- **config/repos.yaml**: Optional per-repo `sanitized_build_command` and `sanitizer_flags` (e.g. `cflags`, `ldflags`).
- **Paths**: Sanitized build output is always `output/<lang>/<repo>/sanitized_build/`.

### Prerequisites

- Clang with AddressSanitizer and UBSan (typical on Linux with clang).
- Repository already cloned (run `vuln-hunter-x clone --repo <name>` first).

---

## Stage 6: Extract fuzz context

Runs CodeQL queries to produce CSVs used when generating fuzz harnesses: function signatures (name, file, line range, parameters) and includes per file.

### Sub-stages

- **6.1 CodeQL queries**: `config/queries/tools/cpp/function_signatures.ql` (one row per parameter), `config/queries/tools/cpp/includes.ql`.
- **6.2 Run extraction**: For each C/C++ database, run these queries via CodeQL CLI and decode BQRS to CSV.
- **6.3 Emit CSVs**: Write `output/<lang>/<repo>/context/function_signatures.csv` and `output/<lang>/<repo>/context/includes.csv`.

### CLI

```bash
vuln-hunter-x extract-fuzz-context              # All C/C++ databases
vuln-hunter-x extract-fuzz-context --repo libucl
vuln-hunter-x extract-fuzz-context --lang cpp --dry-run
```

### Prerequisites

- CodeQL databases for C/C++ repos (run `vuln-hunter-x clone` and create DBs first).
- `CODEQL_PATH` in env or `codeql` on PATH.

---

## Stage 7: Generate fuzz drivers

Generate libFuzzer harness source (`.cc`) from verified findings, then compile/link (7.4–7.6) and optionally run (Stage 8).

### Sub-stages 7.1–7.3 (this command)

- **7.1 Select targets**: From verification results (or SARIF if `--verdict all`), filter by verdict (default: True Positive, Needs More Data). Resolve (file, line) → enclosing function via `functions.csv` or `function_signatures.csv`.
- **7.2 Gather per-target context**: For each target, load signature (params) and includes from Stage 6 CSVs.
- **7.3 Generate harness source**: For each target, write a `.cc` with `#include` from context, `FuzzedDataProvider`, and `LLVMFuzzerTestOneInput` calling the target function. Output: `output/<lang>/<repo>/fuzz_targets/<rule>_<file>_<line>.cc`.

### CLI (generation only)

```bash
vuln-hunter-x generate-fuzz-drivers --repo libucl
vuln-hunter-x generate-fuzz-drivers --verdict tp,nmd   # default
vuln-hunter-x generate-fuzz-drivers --verdict all      # use SARIF only (no verification filter)
vuln-hunter-x generate-fuzz-drivers --dry-run
```

### Prerequisites

- Verification results under `output/<lang>/<repo>/verification_results/` (or use `--verdict all` to use SARIF only).
- Stage 6 context: `output/<lang>/<repo>/context/function_signatures.csv` and `includes.csv`.
- Optionally `functions.csv` (from extract-context) for enclosing function resolution.

### Sub-stages 7.4–7.6 (compile, LLM fix, status)

- **7.4 Compile and link**: For each harness, run `clang++ -c -fsanitize=fuzzer,address -g -O2 -I... harness.cc` then link with Stage 5 manifest (objects/libs from `build_sanitized`). Capture stderr and normalize for LLM.
- **7.5 LLM fix loop (optional)**: If `--llm-fix` and build failed, send harness source + command + errors to LLM; replace source; re-run 7.4; repeat up to `--max-fix-iterations`. Response must contain `LLVMFuzzerTestOneInput`.
- **7.6 Record status**: Per harness: `compiled`, `compile_failed`, `link_failed`, `llm_fix_failed`, or `manifest_missing`. Write `output/<lang>/<repo>/fuzz_targets/status.json`.

### CLI (with build)

```bash
vuln-hunter-x generate-fuzz-drivers --repo libucl --build
vuln-hunter-x generate-fuzz-drivers --build --llm-fix --max-fix-iterations 5
```

| Option | Description |
|--------|-------------|
| `--build` | Compile and link after generating; write status.json |
| `--llm-fix` | Use LLM to fix compile/link errors (Stage 7.5) |
| `--max-fix-iterations N` | Max LLM fix attempts (default 3) |

---

## Stage 8: Run fuzzers (optional)

Run libFuzzer for each harness that reached `compiled` in Stage 7; collect crashes and write a summary.

### Sub-stages

- **8.1 Compile (if needed)**: Binaries are produced in Stage 7.4 next to each `.cc` (no extension). No extra compile step.
- **8.2 Run libFuzzer**: For each binary, run with `-max_total_time=N`, `-artifact_prefix=crash-`, and `ASAN_OPTIONS=abort_on_error=1`. Crashes are written under `output/<lang>/<repo>/fuzz_results/<harness_stem>/`.
- **8.3 Summarize**: Write `output/<lang>/<repo>/fuzz_results/summary.json` with per-harness: `crashed`, `crash_count`, `crash_files`, `time_sec`, `log_snippet`. Map finding → crash yes/no for reporting.

### CLI

```bash
vuln-hunter-x fuzz-run
vuln-hunter-x fuzz-run --repo libucl
vuln-hunter-x fuzz-run --timeout 120 --max-fuzz-time 60
vuln-hunter-x fuzz-run --dry-run
```

| Option | Description |
|--------|-------------|
| `--repo NAME` | Only this repository |
| `--timeout N` | Subprocess timeout per harness in seconds (default 60) |
| `--max-fuzz-time N` | libFuzzer `-max_total_time` (default 30) |
| `--dry-run` | Print actions only |

### Prerequisites

- Harnesses built in Stage 7 (`generate-fuzz-drivers --build`); at least one with status `compiled`.
- libFuzzer and AddressSanitizer (Clang).
