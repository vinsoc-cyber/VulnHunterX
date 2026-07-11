# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 91, `char OOBR_heap = buff4[size3];`, is a heap array read at exactly the allocation size from `malloc(size3)` on line 86, making it a one-past-end out-of-bounds read when allocation succeeds. The value of `size3` is derived from file-controlled `img.width` and `img.height` with no validation or bounds check, and C provides no automatic bounds protection.

## Data flow

attacker-controlled file contents read by fread into img (line 42) → img.width/img.height used to compute size3 (line 82) → malloc(size3) creates buff4 allocation of size3 bytes (line 86) → buff4[size3] reads one byte past the allocation (line 91)

## Answers

1. Step 1: The ultimate source is attacker-controlled file content. `main` passes `argv[1]` to `ProcessImage`, which opens that file at line 33, and `fread(&img,sizeof(img),1,fp)` at line 42 populates `img.width`, `img.height`, and `img.data` from the file. The flagged line is line 91: `char OOBR_heap = buff4[size3];`, which is an array/pointer read from `buff4` at index `size3`.
2. Step 2: Data flow: file selected by `argv[1]` in `main` → `filename` parameter in `ProcessImage` line 29 → `fopen(filename,"r")` line 33 → `fread(&img,sizeof(img),1,fp)` line 42 fills `img` → `size3 = img.width/img.height` line 82 → `malloc(size3)` line 86 allocates `buff4` with exactly `size3` bytes → `buff4[size3]` line 91 reads at offset `size3`, which is one byte past a `size3`-byte allocation.
3. Step 3: No validation, sanitization, or bounds checking is visible. There is no check that `img.height` is nonzero before division at line 82, no check that `size3` is positive or within a safe range before `malloc` at line 86, no check that `malloc` succeeded, and no check that the index used at line 91 is less than the allocation size.
4. Step 4: The sink is line 91: `char OOBR_heap = buff4[size3];`. This is dangerous because `buff4` was allocated with `malloc(size3)` at line 86, so valid byte indexes are `0` through `size3 - 1` when `size3 > 0`; reading `buff4[size3]` is a one-past-the-end heap out-of-bounds read.
5. Step 5: No framework or library automatic protection is visible. `malloc` does not make `buff4[size3]` valid, and C performs no automatic bounds checking on pointer indexing.
6. Step 6: Authentication is not applicable in the shown command-line context. An attacker would need the ability to cause the program to process a chosen file path or file contents via `argv[1]`, as shown by `main` calling `ProcessImage(argv[1])`.
7. Step 7: The concrete impact is memory safety undefined behavior from a heap out-of-bounds read. In this snippet the read value is only assigned to `OOBR_heap` and not visibly output, so the directly visible impact is likely denial of service/crash; depending on allocator/layout and later omitted code, such bugs can also contribute to information disclosure.
8. Step 8: The weakest link is the missing bounds check between allocation and access: `buff4` is allocated for `size3` bytes at line 86, but the code reads index `size3` at line 91 instead of a valid index less than `size3`. There is no visible defense that makes this access safe.
