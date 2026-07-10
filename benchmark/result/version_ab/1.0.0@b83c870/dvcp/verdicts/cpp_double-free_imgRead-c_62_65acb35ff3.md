# cpp/double-free @ imgRead.c:62

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 62 is a real second `free(buff1)` after the unconditional first `free(buff1)` at line 59. The branch condition at line 61 is controlled by file-derived `img.width` and `img.height`, and no visible guard sets `buff1` to NULL or otherwise prevents the double free.

## Data flow

file selected by argv[1] in main → fopen(filename, "r") at line 33 → fread(&img, sizeof(img), 1, fp) at line 42 → img.width/img.height used to compute size1 at line 54 → buff1 = malloc(size1) at line 55 → first free(buff1) at line 59 → condition size1 % 2 == 0 at line 61 → second free(buff1) at line 62

## Answers

1. Step 0 / flagged line: The flagged line is present at line 62 and its exact text is `free(buff1);`. This is a second call to `free` on the same pointer variable `buff1`, matching the cpp/double-free rule. Step 1: The attacker-controlled data originates from the input file selected by `argv[1]` in `main`, which is passed to `ProcessImage` and opened at line 33. File contents are read into `img` at line 42; specifically `img.width` and `img.height` influence `size1` at line 54.
2. Step 2: Data flow: `argv[1]` in `main` selects the file passed to `ProcessImage`; `fopen(filename, "r")` opens it at line 33; `fread(&img, sizeof(img), 1, fp)` reads file-controlled bytes into `img` at line 42; `img.width` and `img.height` are added into `size1` at line 54; `malloc(size1)` allocates memory and assigns it to `buff1` at line 55; `buff1` is freed once at line 59; `size1 % 2 == 0` is tested at line 61; if true, `buff1` is freed again at line 62.
3. Step 3: No validation, sanitization, or encoding sufficient for double-free prevention is visible. The only file-related check is `fp == NULL` at lines 35-39, and the only read check is `fread(...) > 0` at line 42. There is no validation of `img.width`, `img.height`, or `size1`, no `malloc` failure handling, and no assignment of `buff1 = NULL` after the first `free(buff1)` at line 59.
4. Step 4: The sink is line 62, `free(buff1);`. The dangerous operation is freeing the same heap pointer a second time after it was already freed at line 59, on the reachable branch where `size1 % 2 == 0` at line 61.
5. Step 5: No framework or library-level automatic protection is visible. The C standard library `free` does not make double-free safe; calling `free` twice on the same non-NULL pointer is undefined behavior. Some allocators may detect and abort, but that is not a correctness defense shown in this code.
6. Step 6: Based on the provided caller, no authentication or privilege checks are visible. An attacker needs the ability to run the program or influence its command-line argument `argv[1]` and provide a file whose contents are parsed by `ProcessImage`.
7. Step 7: If an attacker controls the file contents, they can influence `size1` via `img.width` and `img.height` at line 54 and make `size1` even, reaching the second `free` at line 62 after the first `free` at line 59. The concrete impact is undefined behavior, typically denial of service through allocator abort/crash, and potentially heap corruption that could contribute to code execution depending on allocator behavior and exploitability.
8. Step 8: The weakest link is the missing lifetime-state defense for `buff1`: after `free(buff1)` at line 59, the pointer remains unchanged and is conditionally freed again at line 62. A complete defense would avoid the second free, set `buff1 = NULL` before any later cleanup path, or restructure ownership so each allocation has exactly one free.
