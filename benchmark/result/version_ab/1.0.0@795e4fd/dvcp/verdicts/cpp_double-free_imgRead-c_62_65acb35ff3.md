# cpp/double-free @ imgRead.c:62

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Flagged line 62 is exactly `free(buff1);`, and the double-free construct is present because `buff1` was already freed at line 59. The branch at line 61 is reachable for even `size1`, which is computed from file-controlled image fields at lines 42 and 54, and no visible guard, sanitizer, or pointer reset prevents the second free.

## Data flow

heap allocation `buff1 = malloc(size1)` (line 55), where `size1` comes from file-controlled `img.width + img.height` (lines 42, 54) → first deallocation `free(buff1)` (line 59) → branch on `size1 % 2 == 0` (line 61) → second deallocation `free(buff1)` (line 62)

## Answers

1. Step 1: The freed pointer `buff1` originates from heap allocation at line 55: `char* buff1=(char*)malloc(size1);`. The branch condition controlling whether the second free executes is derived from file data read into `img` at line 42 via `fread(&img,sizeof(img),1,fp)`, with `size1` computed from `img.width` and `img.height` at line 54. The file name comes from `argv[1]` in `main`, so an attacker who can supply the input file can influence `img.width` and `img.height`.
2. Step 2: Data/control flow: `img` is populated from the file at line 42; `img.width` and `img.height` are added into `size1` at line 54; `size1` is used as the allocation size for `buff1` at line 55; `buff1` is copied into at line 58; `buff1` is freed once at line 59; `size1 % 2 == 0` is checked at line 61; if true, the same `buff1` pointer is freed again at line 62.
3. Step 3: No validation, sanitization, or safe-state reset is visible. There is no check that `buff1` is non-NULL before use, no `buff1 = NULL` after the first `free` at line 59, and no guard preventing the second `free(buff1)` at line 62. There is also no validation of `img.width` or `img.height` before computing `size1` at line 54.
4. Step 4: The sink is line 62: `free(buff1);`. This is dangerous because the same pointer was already freed at line 59, and the line 62 call can therefore double-free the heap allocation.
5. Step 5: No framework or library protection is visible. The C standard library `free` does not provide a source-level guarantee that double-free is safe; calling `free` twice on the same non-NULL pointer is undefined behavior.
6. Step 6: The visible caller `main` accepts a filename from `argv[1]` and passes it to `ProcessImage`. No authentication or privilege checks are visible. This appears triggerable by any local user or process able to run the program with a chosen input file.
7. Step 7: If an attacker controls the file contents, they can choose `img.width` and `img.height` so that `size1 % 2 == 0` at line 61, reaching the second `free` at line 62. Concrete impact is heap corruption and likely denial of service; depending on allocator behavior and environment, double-free can potentially be leveraged for code execution.
8. Step 8: The weakest link is the unconditional first `free(buff1)` at line 59 followed by a reachable conditional second `free(buff1)` at line 62 without nulling the pointer or otherwise preventing reuse. No complete defense is visible.
