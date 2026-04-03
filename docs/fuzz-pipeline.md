# Symbol Analysis Architecture (Stage 5 Internals)

This document explains how Stage 5 (`build-sanitized`) enriches the build manifest
with symbol visibility data, which Stage 7 uses to classify targets and link harnesses.

## Overview

The fuzz pipeline spans Stages 5–8:

```
Stage 5: build-sanitized     → Sanitized build + enriched manifest
Stage 6: extract-fuzz-context → Function signatures, includes (CodeQL)
Stage 7: generate-fuzz-drivers → Select targets → Generate harness → Compile → LLM fix
Stage 8: fuzz-run             → Execute fuzzers, collect & triage crashes
```

> This document covers Stage 5 internals only. For Stage 7 harness generation —
> including linkability classification (7.1) and selective linking (7.4) — see
> [docs/fuzz_stages.md](fuzz_stages.md#stage-7-generate-fuzz-drivers).

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
