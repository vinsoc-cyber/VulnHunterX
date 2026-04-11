# Fuzz-Based Vulnerability Confirmation (Stages 5–8)

Optional pipeline stages to confirm **SAST (CodeQL/Semgrep/OpenGrep) and LLM** findings by building with sanitizers and generating fuzz drivers. The framework uses static analysis (CodeQL, Semgrep, and OpenGrep) to identify vulnerabilities and the LLM to verify them; stages 5–8 add fuzz-based confirmation for C/C++. **C/C++ only.**

## Stage 5: Build with sanitizers

Builds the repository with AddressSanitizer and UBSan in a **separate** directory so the CodeQL database build is untouched. Output is a manifest used to link fuzz harnesses.

### Sub-stages

- **5.1 Prepare build env**: Sets `CC=clang`, `CXX=clang++`, `CFLAGS`/`CXXFLAGS`/`LDFLAGS` with sanitizer flags. Build command comes from `sanitized_build_command` or `build_command` in `config/repos.yaml`.
- **5.2 Run sanitized build**: Copies repo to `output/<lang>/<repo>/sanitized_build/src` and runs the build there (out-of-tree dir `build_sanitized` used when applicable).
- **5.3 Write manifest**: Writes `output/<lang>/<repo>/sanitized_build/manifest.json` with `libs`, `objects`, `include_dirs`, `source_root`, `system_libs`, `compiler_defines` (auto-discovered from `compile_commands.json` or `config.h`), `symbol_to_objects`, `static_symbols`, `lib_exports`, and `manifest_version`. Object files that define a `main()` symbol are automatically filtered out using `nm` to prevent "multiple definition of `main`" link errors with libFuzzer.

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

> **`prepare` context vs Stage 6:** The `prepare` command automatically extracts general-purpose LLM verification context — functions, callers, structs, globals — used by the multi-turn verify engine. Stage 6 (`extract-fuzz-context`) extracts fuzz-specific context — function signatures with parameter types, include directives — used by the harness generator. Both read the same CodeQL database but produce different CSVs for different pipeline consumers.

### Sub-stages

- **6.1 CodeQL queries**: `function_signatures.ql` (one row per parameter), `includes.ql`, `structs.ql` (with member types), `enums.ql`, `typedefs.ql`.
- **6.2 Run extraction**: For each C/C++ database, run these queries via CodeQL CLI and decode BQRS to CSV.
- **6.3 Emit CSVs**: Write to `output/<lang>/<repo>/context/`:
  - `function_signatures.csv` — function name, file, line range, parameter types and names
  - `includes.csv` — file path to include directives
  - `structs.csv` — struct name, member name, **member type** (enables type-aware harness generation)
  - `enums.csv` — enum name, enumerator names and values
  - `typedefs.csv` — typedef name and underlying type

### CLI

```bash
vuln-hunter-x extract-fuzz-context              # All C/C++ databases
vuln-hunter-x extract-fuzz-context --repo libucl
vuln-hunter-x extract-fuzz-context --lang cpp --dry-run
```

### Prerequisites

- CodeQL databases for C/C++ repos (run `vuln-hunter-x clone` and create DBs first).
- `CODEQL_PATH` in env or `codeql` on PATH.

Fuzz driver generation reads SARIF from any analyzer; the function-signature and include context used for harnesses come from the CodeQL database (Stage 6), so for C/C++ fuzz you need at least one CodeQL DB for that repo.

---

## Stage 7: Generate fuzz drivers

Stage 7 runs as two distinct phases under the same command:

```
  Phase A — Harness Generation (always runs)
  ─────────────────────────────────────────
  Command:     vuln-hunter-x generate-fuzz-drivers --repo <name>
  Sub-stages:  7.1 Select targets → 7.2 Gather context → 7.3 Write .cc harnesses

  Phase B — Compilation & Fix (only with --build)
  ────────────────────────────────────────────────
  Command:     vuln-hunter-x generate-fuzz-drivers --repo <name> --build [--llm-fix]
  Sub-stages:  7.4 Compile → 7.5 LLM fix loop → 7.6 Record status
```

Phase A always runs. Phase B only runs when `--build` is passed.
Run Phase A alone to inspect generated harness source before committing to compilation.

### Phase A — Harness Generation

#### 7.1 Select targets

Filters findings by verdict (default: True Positive + Needs More Data), resolves each (file, line) pair to its enclosing function via `functions.csv` or `function_signatures.csv`, excludes functions named `main`, scores fuzzability, and deduplicates (highest-severity kept when multiple findings hit the same function).

**Fuzzability scoring:** +10 per primitive parameter, +8 for buffer+length pattern, +15 for memory corruption CWEs (119, 120, 416, 787), +2 per known caller, −5 for single-caller private helpers.

**Linkability classification:** Each candidate is assigned a category based on symbol visibility in the Stage 5 manifest:

| Category | Score Bonus | Description | Link strategy |
|---|---|---|---|
| `library_exported` | +20 | Symbol exported in a `.a` library | Link the `.a` (ideal) |
| `object_global` | +5 | Global symbol in a `.o`, not in any library | Link the specific `.o` |
| `static` | −15 | File-scoped (`static`) function | Skip (or source-include) |
| `executable_source` | −25 | In a file that defines `main()` | Skip |

Classification priority:
1. Check `lib_exports` (Stage 5 manifest) → `library_exported`
2. Check CodeQL `is_static` column → `static`
3. Check `static_symbols` (from `nm`) → `static`
4. Check `symbol_to_objects` + `main()` detection → `object_global` or `executable_source`
5. Fallback → `unknown`

Targets classified as `static` or `executable_source` are **skipped** with a logged warning:

```
WARNING: Skipping 'decomp' (src/tjbench.c:176): static function, not linkable from external harness
WARNING: Skipping 'parse_switches' (src/djpeg.c:182): executable-local function (file contains main())
```

Skipped targets are recorded in `output/<lang>/<repo>/fuzz_targets/skipped_targets.json` and also included in `status.json` under the `"skipped_targets"` key.

> Symbol data comes from the manifest produced by Stage 5. See [docs/fuzz-pipeline.md](fuzz-pipeline.md) for how `nm` and `compile_commands.json` populate the symbol map.

#### 7.2 Gather per-target context

For each target, load function signature (parameters), include directives, struct definitions, enum values, and typedefs from Stage 6 CSVs (`function_signatures.csv`, `includes.csv`, `structs.csv`, `enums.csv`, `typedefs.csv`).

#### 7.3 Generate harness source

For each target, write a `.cc` file with `#include` directives from context, a `FuzzedDataProvider`, and a `LLVMFuzzerTestOneInput` entry point that calls the target function.

**Type-aware generation:** Parameter types are initialized using their actual C/C++ type. The generator applies six key techniques informed by Futag, OSS-Fuzz-Gen, and Google's fuzzing best practices:

| C/C++ type | FuzzedDataProvider call | Notes |
|---|---|---|
| `char*` | `ConsumeRandomLengthString(256)` | Bounded string (avoids data starvation) |
| `uint8_t*` / `void*` | `ConsumeBytes<uint8_t>(bounded)` | Bounded buffer, not `ConsumeRemainingBytes` |
| `size_t` (paired with buffer) | `buf.size()` | **Correlated** with actual buffer length |
| `size_t` (standalone) | `ConsumeIntegral<size_t>()` | |
| `int` / `long` | `ConsumeIntegral<T>()` | |
| `bool` | `ConsumeBool()` | |
| `float` / `double` | `ConsumeFloatingPoint<T>()` | |
| `enum` type | `PickValueInArray({VAL_A, VAL_B, ...})` | Uses actual enum constants from `enums.csv` |
| typedef'd type | Resolved to underlying type | Follows typedef chains from `typedefs.csv` |
| `FILE*` | `fmemopen()` with fuzzed content | Standard pattern from Google fuzzing docs |
| struct member | member-type-specific call | Uses `structs.csv` `member_type` column |
| `char [N]` member | `ConsumeBytesAsString(N-1)` + memcpy | Fills char arrays with fuzzed data |

**Buffer + size correlation:** When a buffer pointer parameter (e.g. `const uint8_t *data`) is followed by a size parameter (e.g. `size_t len`), the generator produces correlated code where the size is derived from the actual buffer length. This prevents the #1 harness quality issue: independent buffer/size values causing instant OOB crashes. Detection uses adjacency heuristics and parameter name matching (`len`, `size`, `count`, `nbytes`, etc.).

**Consumption ordering:** Fixed-size items (scalars, enums) are consumed first, followed by bounded strings, then buffers. This follows Google's FuzzedDataProvider best practice of consuming deterministic items before variable-length data to prevent input starvation.

**Typedef resolution:** Parameters whose types are typedefs (e.g. `ucl_type_t`) are resolved through the typedef chain (from `typedefs.csv`) before looking up struct/enum definitions. This enables correct struct initialization and enum value selection for typedef'd types.

Output: `output/<lang>/<repo>/fuzz_targets/<rule>_<file>_<line>.cc`.

### Phase A CLI — Harness Generation

```bash
vuln-hunter-x generate-fuzz-drivers --repo libucl
vuln-hunter-x generate-fuzz-drivers --verdict tp,nmd   # default
vuln-hunter-x generate-fuzz-drivers --verdict all      # use SARIF only (no verification filter)
vuln-hunter-x generate-fuzz-drivers --dry-run
```

### Prerequisites (Phase A)

- Verification results under `output/<lang>/<repo>/verification_results/` (or use `--verdict all` to use SARIF only).
- Stage 6 context: `output/<lang>/<repo>/context/function_signatures.csv` and `includes.csv`.
- Optionally `functions.csv` (from extract-context) for enclosing function resolution.

---

### Phase B — Compilation & Fix

#### 7.4 Compile and link

For each harness, run `clang++ -c -fsanitize=fuzzer,address -g -O2 -D... -I... harness.cc` then link with the Stage 5 manifest (objects/libs). Compiler defines from the manifest (`compiler_defines`) are automatically included. Extra paths can be specified via config or CLI.

**Selective linking:** Instead of linking all objects into every harness, Stage 7.4 resolves minimal dependencies per linkability category:
- `library_exported` → link only the `.a` file(s) containing the symbol
- `object_global` → link the specific `.o` + transitive libraries
- `static` → compile the `.c` source alongside the harness (source inclusion, Futag-inspired)
- `unknown` → fallback to all objects + all libraries

See [docs/fuzz-pipeline.md](fuzz-pipeline.md) for the Futag-inspired source-inclusion technique details.

#### 7.5 LLM fix loop (optional)

If `--llm-fix` and build failed, send harness source + command + errors to LLM; replace source; re-run 7.4; repeat up to `--max-fix-iterations`. Response must contain `LLVMFuzzerTestOneInput`.

The fix loop uses **multi-turn conversation** (message history preserved across iterations so the LLM knows what it already tried). Errors are **classified** (linker, missing_include, undefined_symbol, type_mismatch) with targeted hints. The LLM additionally receives:
- Symbol context (which symbols are `library_exported` vs `static`)
- Enhanced error classification for `multiple definition of main` (suggests the `#define main __original_main_disabled` trick)
- Per-file compiler flags from `compile_commands.json`

Type context budget is 4000 chars.

#### 7.6 Record status

Per harness: `compiled`, `compile_failed`, `link_failed`, `llm_fix_failed`, or `manifest_missing`. Write `output/<lang>/<repo>/fuzz_targets/status.json`.

### Phase B CLI — Compilation & Fix

```bash
vuln-hunter-x generate-fuzz-drivers --repo libucl --build
vuln-hunter-x generate-fuzz-drivers --build --llm-fix --max-fix-iterations 5
```

| Option | Description |
|--------|-------------|
| `--build` | Compile and link after generating; write status.json |
| `--llm-fix` | Use LLM to fix compile/link errors (Stage 7.5) |
| `--max-fix-iterations N` | Max LLM fix attempts (default: from config `fuzz.max_fix_iterations`, fallback 5) |
| `--extra-include-dir PATH` | Extra `-I` path for harness compilation (repeatable) |
| `--extra-lib-dir PATH` | Extra `-L` path for harness linking (repeatable) |
| `--extra-link-lib LIB` | Extra `-l` library for harness linking (repeatable) |

### Configuration

Fuzz pipeline settings in `config/confirm_findings.yaml` under the `fuzz:` section:

```yaml
fuzz:
  max_fix_iterations: 5        # Max LLM fix attempts (Stage 7.5)
  extra_include_dirs: []        # Extra -I paths for harness compilation
  extra_lib_dirs: []            # Extra -L paths for harness linking
  extra_link_libs: []           # Extra -l libraries (e.g. ["m", "pthread"])
  extra_cflags: []              # Extra compiler flags
  extra_ldflags: []             # Extra linker flags
```

Environment variable: `MAX_FIX_ITERATIONS` overrides `fuzz.max_fix_iterations`.

Priority: CLI args > env vars > config file > defaults.

> **Note:** The `--llm-fix` loop uses the same LLM provider/model configured in `.env`
> (`LLM_PROVIDER`, `LLM_MODEL`). For OpenAI-compatible endpoints (DashScope, Azure, etc.),
> set `OPENAI_BASE_URL` — the fix loop will automatically prefix the model with `openai/`.

> **Important:** If harnesses show type errors (e.g. assigning scalars to array/struct members),
> re-run `vuln-hunter-x prepare --skip-clone --skip-db --force --repo <name>` to regenerate context CSVs with the latest CodeQL queries.
> The `structs.csv` must include the `member_type` column for type-aware harness generation.

---

## Stage 8: Run fuzzers (optional)

Run libFuzzer for each harness that reached `compiled` in Stage 7; collect crashes and write a summary.

### Sub-stages

- **8.1 Ensure binaries**: Binaries are produced in Stage 7.4 next to each `.cc` (no extension). No extra compile step.
- **8.2 Run libFuzzer**: For each binary, run with `-max_total_time=N`, `-artifact_prefix=crash-`, and `ASAN_OPTIONS=abort_on_error=1`. Optionally pass a persistent corpus directory and `-rss_limit_mb=N`. Crashes are written under `output/<lang>/<repo>/fuzz_results/<harness_stem>/`. Supports **parallel execution** via `ProcessPoolExecutor`.
- **8.3 Crash triage (optional)**: When `--triage` is enabled, each crash input is re-run against the binary to extract the ASan/UBSan stack trace. Crashes are **deduplicated by stack hash** (top 5 frames) and **classified by severity** (e.g. heap-buffer-overflow → Critical, null-dereference → Medium). Results are added to summary.json.
- **8.4 Summarize**: Write `output/<lang>/<repo>/fuzz_results/summary.json` with per-harness: `crashed`, `crash_count`, `crash_files`, `time_sec`, `log_snippet`, and optionally `unique_crash_count` and `triaged_crashes` (each with `crash_type`, `stack_hash`, `faulting_function`, `severity`).

### CLI

```bash
vuln-hunter-x fuzz-run
vuln-hunter-x fuzz-run --repo libucl
vuln-hunter-x fuzz-run --timeout 120 --max-fuzz-time 60
vuln-hunter-x fuzz-run --triage --parallel 4
vuln-hunter-x fuzz-run --corpus --rss-limit 2048
vuln-hunter-x fuzz-run --dry-run
```

| Option | Description |
|--------|-------------|
| `--repo NAME` | Only this repository |
| `--timeout N` | Subprocess timeout per harness in seconds (default 60) |
| `--max-fuzz-time N` | libFuzzer `-max_total_time` (default 30) |
| `--dry-run` | Print actions only |
| `--triage` | Triage crashes: extract stack traces, deduplicate by hash, classify severity |
| `--parallel N` | Run N harnesses in parallel (default 1) |
| `--corpus` | Use persistent corpus directories under `fuzz_corpus/` |
| `--rss-limit N` | RSS memory limit per fuzzer in MB (0 = unlimited) |

### Prerequisites

- Harnesses built in Stage 7 (`generate-fuzz-drivers --build`); at least one with status `compiled`.
- libFuzzer and AddressSanitizer (Clang).
