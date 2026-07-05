# cpp/double-free @ imgRead.c:62

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The reported CWE-415 construct is directly visible: `buff1` is freed at line 59 and the same pointer is freed again at flagged line 62 when `size1` is even. No visible validation or ownership guard prevents this path, and `size1` is derived from file-controlled `img.width` and `img.height`.

## Data flow

argv[1] in main → ProcessImage(filename) → fopen(filename, "r") at Statement 1 → fread(&img, sizeof(img), 1, fp) reads file-controlled struct fields → size1 = img.width + img.height around line 55 → buff1 = malloc(size1) around line 56 → free(buff1) at line 59 → if (size1 % 2 == 0) around line 61 → free(buff1) again at flagged line 62

## Answers

1. Step 1: The ultimate external input originates from the command-line argument `argv[1]` in `main`, which is passed to `ProcessImage(argv[1])` in the pre-fetched caller context. Inside `ProcessImage`, this becomes `filename` and is opened with `fopen(filename, "r")` at Statement 1. The image contents are then read from that file into `img` by `fread(&img, sizeof(img), 1, fp)` in the loop. The values `img.width` and `img.height` from the file influence `size1`, which controls whether the second `free(buff1)` is reached.
2. Step 2: Data/control flow: `argv[1]` in `main` → `ProcessImage(argv[1])` → `filename` → `fopen(filename, "r")` at Statement 1 → `fread(&img, sizeof(img), 1, fp)` reads file-controlled data into `img` → `img.width + img.height` assigns `size1` around line 55 → `malloc(size1)` assigns allocated pointer to `buff1` around line 56 → `free(buff1)` at line 59 → `if (size1 % 2 == 0)` around line 61 → second `free(buff1)` at flagged line 62.
3. Step 3: No validation, sanitization, or encoding relevant to double-free is visible. There is a check that `fp == NULL` after `fopen`, but that only validates file opening, not the image fields or pointer lifetime. There is no check preventing reuse of `buff1` after `free(buff1)` at line 59, no `buff1 = NULL`, and no guard ensuring the second `free(buff1)` at line 62 is skipped after the first free.
4. Step 4: The sink is the second `free(buff1)` at flagged line 62. The dangerous operation is freeing the same heap pointer after it was already freed unconditionally at line 59, producing a double-free when `size1 % 2 == 0`.
5. Step 5: No framework or library-level automatic protection is visible. Standard C `free()` does not make a second free of the same non-NULL pointer safe; calling `free()` twice on the same allocation without intervening reallocation is undefined behavior.
6. Step 6: Based on the provided caller, an attacker needs the ability to invoke the program with a chosen file path as `argv[1]` and control that file's contents. No authentication or privilege checks are visible in the provided context.
7. Step 7: If an attacker controls the image file contents, they can choose `img.width` and `img.height` so that `size1` is even, reaching the second `free(buff1)`. The concrete impact is heap corruption / allocator metadata corruption, which can cause denial of service and may potentially be exploitable for code execution depending on allocator and runtime hardening.
8. Step 8: The weakest link is pointer lifetime management: `buff1` is unconditionally freed at line 59 and then conditionally freed again at line 62 without nulling the pointer, tracking ownership, or using an `else`/single-cleanup structure. There is no complete defense visible.
