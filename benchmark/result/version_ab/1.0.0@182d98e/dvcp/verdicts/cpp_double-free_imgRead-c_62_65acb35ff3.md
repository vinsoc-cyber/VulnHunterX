# cpp/double-free @ imgRead.c:62

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged sink at line 62 is a second `free(buff1)` after an unconditional first `free(buff1)` at line 59. The branch at line 61 is reachable when file-controlled `img.width + img.height` is even, and there is no visible nulling, reallocation, or lifetime guard between the two frees.

## Data flow

file path from argv[1] in main → filename parameter at line 29 → fopen(filename, "r") at line 33 → fread(&img, sizeof(img), 1, fp) at line 42 → img.width/img.height used to compute size1 at line 54 → buff1 = malloc(size1) at line 55 → first free(buff1) at line 59 → branch on size1 % 2 == 0 at line 61 → second free(buff1) sink at line 62

## Answers

1. Step 0 / flagged line: The flagged line is present at line 62 and its exact text is `free(buff1);`. This is a second `free` operation on the same pointer variable `buff1`, matching the cpp/double-free construct.
2. Step 1: The relevant attacker-controlled input originates from the file named by `argv[1]` in `main`, which is passed to `ProcessImage(argv[1])` in the provided caller context. Inside `ProcessImage`, the file is opened at line 33 and binary data is read into `img` at line 42. The fields `img.width` and `img.height` are then used at line 54 to compute `size1`, which controls whether the second free is reached at line 61.
3. Step 2: Data flow: `argv[1]` in `main` → `filename` parameter of `ProcessImage` at line 29 → `fopen(filename, "r")` at line 33 → `fread(&img, sizeof(img), 1, fp)` at line 42 populates `img` → `img.width + img.height` assigned to `size1` at line 54 → `size1` passed to `malloc(size1)` and result assigned to `buff1` at line 55 → `buff1` is freed at line 59 → `size1 % 2 == 0` checked at line 61 → `buff1` is freed again at line 62.
4. Step 3: There is no validation or sanitization visible for `img.width`, `img.height`, or `size1` before line 61. There is also no lifetime defense after the first `free(buff1)` at line 59: `buff1` is not set to `NULL`, not reallocated, and not otherwise guarded before the second `free(buff1)` at line 62. The check `size1 % 2 == 0` at line 61 is not a double-free prevention; it is merely a branch condition.
5. Step 4: The sink is line 62, `free(buff1);`. The dangerous operation is freeing the same heap pointer a second time after it was already freed at line 59, which is CWE-415 double free.
6. Step 5: No framework-level or library-level automatic protection is visible. The C standard library `free` does not make repeated frees of the same non-NULL pointer safe; freeing an already-freed pointer is undefined behavior. No allocator-specific hardening can be assumed from the provided code.
7. Step 6: Based on the provided caller, an attacker needs the ability to run the program or influence the command-line input file path `argv[1]`, and to supply file contents read by `fread` at line 42. No authentication or privilege checks are visible in the provided context.
8. Step 7: If an attacker controls the file contents, they can choose `img.width` and `img.height` so that `size1` is even, reaching line 62 after line 59. The concrete impact is at least denial of service via allocator abort/crash, and potentially heap corruption that may lead to more severe exploitation depending on allocator behavior.
9. Step 8: The weakest link is the missing ownership/lifetime guard after line 59. The pointer `buff1` remains unchanged after the first free, and line 61 conditionally allows execution to reach a second `free(buff1)` at line 62 with no nulling, reallocation, or other visible defense.
