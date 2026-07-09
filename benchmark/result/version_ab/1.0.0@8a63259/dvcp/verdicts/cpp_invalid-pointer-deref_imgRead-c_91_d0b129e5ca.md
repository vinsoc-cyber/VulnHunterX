# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 91 dereferences `buff4[size3]` after `buff4` was allocated with exactly `size3` bytes at line 86, making the index one past the valid heap allocation range when `size3` is positive. The value of `size3` is derived from untrusted file fields read at line 42 and there is no visible validation or bounds check before the unsafe read.

## Data flow

attacker-controlled file content read by fread into img (line 42) → img.width/img.height used to compute size3 (line 82) → malloc(size3) assigns allocation to buff4 (line 86) → buff4 indexed with size3 at sink (line 91)

## Answers

1. Step 0 / flagged line: Line 91 is present and reads exactly `char OOBR_heap = buff4[size3];`. This is an array/pointer read from `buff4` using index `size3`, matching the `cpp/invalid-pointer-deref` construct: a potentially out-of-bounds pointer dereference/read.
2. Step 1: The dangerous data ultimately originates from attacker-controlled file content. `main` passes `argv[1]` to `ProcessImage`, which opens that file at line 33 and reads bytes into `img` using `fread(&img,sizeof(img),1,fp)` at line 42. The fields `img.width`, `img.height`, and `img.data` are therefore file-derived.
3. Step 2: Data flow: file path from `argv[1]` in `main` → `ProcessImage(filename)` → `fopen(filename,"r")` at line 33 → `fread(&img,sizeof(img),1,fp)` at line 42 populates `img` → `size3 = img.width/img.height` at line 82 → `buff4 = malloc(size3)` at line 86 → `memcpy(buff4,img.data,sizeof(img.data))` at line 87 → out-of-bounds read `buff4[size3]` at line 91.
4. Step 3: No validation, sanitization, or bounds checking is visible for `img.width`, `img.height`, `size3`, `buff4`, or the index used at line 91. There is no check that `img.height` is nonzero before line 82, no check that `size3` is positive, no check that `malloc` succeeded at line 86, and no check that the read index is less than the allocation size before line 91.
5. Step 4: The sink is line 91: `char OOBR_heap = buff4[size3];`. This is dangerous because `buff4` is allocated with exactly `size3` bytes at line 86, so valid positive indexes would be `0` through `size3 - 1`; reading `buff4[size3]` is a one-past-the-end heap read.
6. Step 5: No framework-level or library-level automatic protection is visible. `malloc` allocates raw memory and does not provide bounds-checked indexing in C. Native C array/pointer access at line 91 has no automatic bounds checking.
7. Step 6: Based on the provided caller, an attacker needs the ability to cause the program to process a chosen file path/content via the command-line argument `argv[1]`. No authentication or privilege checks are visible in the provided context.
8. Step 7: The concrete security impact is an out-of-bounds heap read, which can cause denial of service via crash and may disclose adjacent heap memory depending on how the read value is used or observed. The same surrounding code also has other memory safety issues, but for this specific finding the impact is CWE-125-style out-of-bounds read.
9. Step 8: The weakest link is the absence of any bounds check before line 91. The code allocates `size3` bytes at line 86 and then reads exactly one byte past that allocation at line 91 using index `size3`.
