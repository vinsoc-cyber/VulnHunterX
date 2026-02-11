# Fuzz-Based Vulnerability Confirmation (Stages 5–8)

Optional pipeline stages to confirm CodeQL/LLM findings by building with sanitizers and generating fuzz drivers. **C/C++ only.**

## Stage 5: Build with sanitizers

Builds the repository with AddressSanitizer and UBSan in a **separate** directory so the CodeQL database build is untouched. Output is a manifest used to link fuzz harnesses.

### Sub-stages

- **5.1 Prepare build env**: Sets `CC=clang`, `CXX=clang++`, `CFLAGS`/`CXXFLAGS`/`LDFLAGS` with sanitizer flags. Build command comes from `sanitized_build_command` or `build_command` in `config/repos.yaml`.
- **5.2 Run sanitized build**: Copies repo to `builds/<lang>/<repo>/src` and runs the build there (out-of-tree dir `build_sanitized` used when applicable).
- **5.3 Write manifest**: Writes `builds/<lang>/<repo>/manifest.json` with `libs`, `objects`, `include_dirs`, and `source_root`.

### CLI

```bash
codeql-llm build-sanitized --repo <name>   # Build one repo
codeql-llm build-sanitized --lang cpp      # All C++ repos
codeql-llm build-sanitized --repo libucl -f  # Force rebuild
codeql-llm build-sanitized --dry-run       # Preview
```

### Config

- **config/repos.yaml**: Optional per-repo `sanitized_build_command` and `sanitizer_flags` (e.g. `cflags`, `ldflags`).
- **Paths**: `builds_dir` (default `builds/`) can be set in `config/confirm_findings.yaml` under `paths.builds_dir`.

### Prerequisites

- Clang with AddressSanitizer and UBSan (typical on Linux with clang).
- Repository already cloned (run `codeql-llm clone --repo <name>` first).

---

## Stage 6: Extract fuzz context

Runs CodeQL queries to produce CSVs used when generating fuzz harnesses: function signatures (name, file, line range, parameters) and includes per file.

### Sub-stages

- **6.1 CodeQL queries**: `config/queries/tools/cpp/function_signatures.ql` (one row per parameter), `config/queries/tools/cpp/includes.ql`.
- **6.2 Run extraction**: For each C/C++ database, run these queries via CodeQL CLI and decode BQRS to CSV.
- **6.3 Emit CSVs**: Write `output/context/<repo>/function_signatures.csv` and `output/context/<repo>/includes.csv`.

### CLI

```bash
codeql-llm extract-fuzz-context              # All C/C++ databases
codeql-llm extract-fuzz-context --repo libucl
codeql-llm extract-fuzz-context --lang cpp --dry-run
```

### Prerequisites

- CodeQL databases for C/C++ repos (run `codeql-llm clone` and create DBs first).
- `CODEQL_PATH` in env or `codeql` on PATH.

---

Stages 7–8 are documented as they are implemented.
