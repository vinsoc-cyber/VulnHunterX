# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line is present at line 91: `char OOBR_heap = buff4[size3];`, which is a heap pointer/array read. Because `buff4` is allocated with exactly `size3` bytes on line 86 and then read at index `size3` on line 91 with no intervening bounds check or sanitization, the read is one past the allocated buffer for positive `size3` and is clearly an out-of-bounds read.

## Data flow

attacker-controlled file path/content via argv[1] in main → fopen(filename, "r") at line 33 → fread(&img, sizeof(img), 1, fp) at line 42 → file-controlled img.width/img.height → size3 = img.width / img.height at line 82 → buff4 = malloc(size3) at line 86 → out-of-bounds read buff4[size3] at line 91

## Answers

1. Step 1: The ultimate attacker-controlled source is the input file named by `argv[1]` in `main`, which is passed to `ProcessImage` and opened at line 33. File contents are read into `img` using `fread(&img, sizeof(img), 1, fp)` at line 42, so `img.width` and `img.height` are file-controlled.
2. Step 2: Data flow: `argv[1]` is passed to `ProcessImage` by `main`; `ProcessImage` opens it at line 33; `fread` populates `img` at line 42; `img.width` and `img.height` are used to compute `size3 = img.width / img.height` at line 82; `size3` is passed to `malloc(size3)` at line 86 to allocate `buff4`; `buff4` is then read at index `size3` on line 91.
3. Step 3: No validation, sanitization, or bounds checking is visible. There is no check that `img.height` is nonzero before division at line 82, no check that `size3` is positive or within an expected range before `malloc` at line 86, no check that `malloc` succeeded, and no check that `size3` is a valid index before `buff4[size3]` at line 91.
4. Step 4: The sink is the array/pointer read on line 91: `char OOBR_heap = buff4[size3];`. This is dangerous because `buff4` was allocated with exactly `size3` bytes at line 86, so valid positive indexes are `0` through `size3 - 1`; reading `buff4[size3]` reads one byte past the allocated heap buffer.
5. Step 5: No framework or library protection is visible. This is C code using raw `malloc`, `memcpy`, and pointer indexing; C provides no automatic bounds checking for `buff4[size3]` at line 91.
6. Step 6: The provided caller shows `main` accepts a filename from `argv[1]` and passes it directly to `ProcessImage`. Based on visible context, an attacker needs the ability to run the program or otherwise supply the input file path/content. No authentication or privilege checks are visible.
7. Step 7: If an attacker controls the file contents, they can control `img.width` and `img.height`, thereby influencing `size3`. The specific impact of the flagged read is out-of-bounds heap read, which can cause information disclosure or a crash/DoS. The same index is later used for a heap write at line 95, but the reported sink is the read at line 91.
8. Step 8: The weakest link is the absence of any bounds check between allocating `buff4` with `malloc(size3)` at line 86 and reading `buff4[size3]` at line 91. The code reads exactly one element past the allocated object for positive `size3`, and there is no visible defense preventing that path.
