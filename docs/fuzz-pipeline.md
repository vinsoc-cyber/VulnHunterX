# Fuzz Pipeline: Symbol-Aware Target Generation

This document describes VulnHunterX's enhanced fuzz target generation pipeline,
which uses symbol visibility analysis and dependency-aware compilation — inspired
by the [Futag](https://github.com/ispras/Futag) project's methodology.

## Overview

The fuzz pipeline spans Stages 5–8:

```
Stage 5: build-sanitized     → Sanitized build + enriched manifest
Stage 6: extract-fuzz-context → Function signatures, includes (CodeQL)
Stage 7: generate-fuzz-drivers → Select targets → Generate harness → Compile → LLM fix
Stage 8: fuzz-run             → Execute fuzzers, collect & triage crashes
```

The key enhancement is in **Stage 5** (manifest enrichment) and **Stage 7.1**
(linkability-aware target selection), which prevent the generation of
unfuzzable harnesses.

## Symbol Analysis (Stage 5)

After the sanitized build completes, `write_manifest()` enriches the manifest
with three additional data sources:

### 1. Symbol-to-Object Map (`nm` on `.o` files)

Runs `nm --defined-only` on every `.o` file under the build tree.

- **`T` (uppercase)**: Global text symbol — visible to the linker from other
  translation units. These functions can be called from an external harness.
- **`t` (lowercase)**: Local/static text symbol — file-scoped, invisible to
  the linker. Cannot be called from a separate `.cc` harness file.

Stored in `manifest.json` as:
```json
{
  "symbol_to_objects": {
    "jpeg_read_header": ["build_sanitized/CMakeFiles/jpeg.dir/src/jdapimin.c.o"]
  },
  "static_symbols": ["decomp", "fullTest", "compTest"]
}
```

### 2. Library Export Map (`nm` on `.a` files)

Runs `nm -g --defined-only` on each static library to identify which symbols
are exported. This is the gold standard for fuzzability — if a function is in
a `.a` library, a harness can link against it.

```json
{
  "lib_exports": {
    "jpeg_read_header": ["build_sanitized/libjpeg.a"],
    "tjCompress2": ["build_sanitized/libturbojpeg.a"]
  }
}
```

### 3. Compile Commands (`compile_commands.json`)

For CMake projects, the build injects `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.
This captures exact per-file compiler flags (`-D`, `-I`, `-std`, etc.),
enabling harness compilation with the project's real build configuration.

```json
{
  "compile_commands": {
    "src/tjbench.c": {
      "directory": "/path/to/build",
      "command": "clang -DFOO=1 -Iinclude -c src/tjbench.c",
      "file": "/path/to/src/tjbench.c"
    }
  }
}
```

## Linkability Classification (Stage 7.1)

Each candidate fuzz target is classified into one of four categories:

| Category | Score Bonus | Description | Strategy |
|---|---|---|---|
| `library_exported` | +20 | Symbol exported in a `.a` library | Link against the library (ideal) |
| `object_global` | +5 | Global in a `.o` but not in any library | Link specific `.o` files |
| `static` | -15 | `static` or file-local function | Source-inclusion or skip |
| `executable_source` | -25 | In a file containing `main()` | Skip (standalone tool) |

Classification priority:
1. Check `lib_exports` → `library_exported`
2. Check CodeQL `is_static` column → `static`
3. Check `static_symbols` (from `nm`) → `static`
4. Check `symbol_to_objects` + `main()` detection → `object_global` or `executable_source`
5. Fallback → `unknown`

## Unfuzzable Target Handling

Targets classified as `static` or `executable_source` are **skipped** with a
logged warning:

```
WARNING: Skipping 'decomp' (src/tjbench.c:176): static function, not linkable from external harness
WARNING: Skipping 'parse_switches' (src/djpeg.c:182): executable-local function (file contains main())
```

Skipped targets are recorded in `output/<lang>/<repo>/fuzz_targets/skipped_targets.json`:

```json
{
  "skipped_targets": [
    {
      "function": "decomp",
      "file": "src/tjbench.c",
      "line": 176,
      "reason": "static function, not linkable from external harness",
      "linkability": "static"
    }
  ]
}
```

They are also included in `status.json` under the `"skipped_targets"` key.

## Selective Linking (Stage 7.4)

Instead of dumping all 100+ object files into every link command, the builder
resolves minimal dependencies per target:

- **Library-exported**: Link only the `.a` file(s) containing the symbol
- **Object-global**: Link the specific `.o` file + libraries for transitive deps
- **Static**: Compile the source `.c` file alongside (without `-fsanitize=fuzzer`)
- **Unknown**: Fall back to all objects + all libraries (legacy behavior)

This produces cleaner link commands and avoids symbol conflicts.

## Static Function Strategy (Futag-Inspired)

For static functions that pass through the filter (e.g. manually forced), the
harness uses **source inclusion** — directly `#include`-ing the `.c` file:

```c
/* Stub out main() to avoid linker conflict */
#define main __original_main_disabled
#include "/path/to/tjbench.c"
#undef main

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Can now call decomp() directly since it's in our translation unit
    decomp(...);
    return 0;
}
```

This technique comes from the [Futag project](https://github.com/ispras/Futag)
and is common in fuzz target generation for C libraries.

## LLM Fix Loop (Stage 7.5)

When harness compilation fails, the LLM fix loop now receives additional
context:

- **Symbol context**: which symbols are library-exported vs static
- **Enhanced error classification**: detects `multiple definition of main`
  and suggests the `#define main` trick
- **Project compile flags**: from `compile_commands.json`

The system prompt teaches the LLM about source-inclusion and extern linkage
techniques.

## Troubleshooting

### All harnesses fail with "undefined reference"

**Cause**: Targets are static/file-local functions not exported in any library.

**Fix**: Re-run with the enriched manifest. The pipeline will now skip
unfuzzable targets and prefer library-exported functions. Check
`skipped_targets.json` for details.

### "multiple definition of `main`"

**Cause**: A harness `#include`s a `.c` file that contains `main()`.

**Fix**: The generator adds `#define main __original_main_disabled` automatically.
If the LLM fix loop encounters this, it will suggest the same fix.

### No fuzzable targets found

**Cause**: All candidate functions from SARIF findings are static or in
executable sources.

**Fix**: Use `--verdict all` to consider all SARIF findings (not just verified
ones). Library API functions like `jpeg_read_header` are more likely to be
fuzzable.

### Compile errors from `#include "file.c"`

**Cause**: The included source has dependencies not satisfied by the harness's
include paths.

**Fix**: The builder extracts `-D` and `-I` flags from `compile_commands.json`.
If this file is missing (non-CMake projects), manually add include paths to
the manifest.

## Futag Reference

This pipeline's symbol analysis and source-inclusion approach is inspired by:

- **Futag** (FUzzing Target Automated Generator) — ISP RAS
  - [GitHub](https://github.com/ispras/Futag)
  - [Paper: "Enhancing Fuzz Testing Efficiency through Automated Fuzz Target Generation"](https://link.springer.com/article/10.1134/S0361768825700227)
  - [IEEE: "Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749)

Key Futag concepts adopted:
1. **compile_commands.json** extraction for accurate build flags
2. **Symbol dependency analysis** before harness generation
3. **Static function handling** via source inclusion
4. **Library vs executable distinction** for target prioritization
