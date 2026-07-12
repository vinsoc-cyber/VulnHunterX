# cpp/invalid-pointer-deref @ imgRead.c:95

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 95 is exactly `buff4[size3]='c';`, an indexed write through a pointer allocated by `malloc(size3)` at line 86. Because valid indexes for a `size3`-byte allocation do not include `size3`, and no validation or bounds check occurs before the write, attacker-influenced file fields can drive a heap out-of-bounds write.

## Data flow

file contents opened via argv[1] in main → fread(&img,sizeof(img),1,fp) populates img at line 42 → img.width/img.height compute size3 at line 82 → malloc(size3) returns buff4 at line 86 → buff4[size3]='c' writes one byte out of bounds at line 95

## Answers

1. Q1 / Step 1: The flagged line is present at line 95: `buff4[size3]='c';`, and it is an indexed write through a malloc-derived pointer. The dangerous data ultimately originates from attacker-controlled file contents read into `img` by `fread(&img,sizeof(img),1,fp)` at line 42. The filename itself comes from `argv[1]` in `main`, then is passed to `ProcessImage(argv[1])`; the file contents populate `img.width` and `img.height`, which influence `size3`.
2. Q2 / Step 2: Data flow: `argv[1]` is passed to `ProcessImage` as `filename` in `main`; `fopen(filename,"r")` opens that file at line 33; `fread(&img,sizeof(img),1,fp)` reads file-controlled bytes into `img` at line 42; `img.width` and `img.height` are used to compute `int size3 = img.width/img.height;` at line 82; `size3` is passed to `malloc(size3)` at line 86 and the returned pointer is assigned to `buff4`; `buff4` is then indexed with `size3` at line 95 in `buff4[size3]='c';`.
3. Q3 / Step 3: No sufficient validation or sanitization is visible. The code checks only whether `fp == NULL` at lines 35-39. There is no validation of the file header because the header check is commented out at lines 44-45 and 117-119. There is no check that `img.height` is nonzero before division at line 82, no check that `size3` is positive or within a safe range before `malloc(size3)` at line 86, no check that `malloc` succeeded, and no bounds check before writing `buff4[size3]` at line 95. The `if(size3>10)` check at line 97 occurs after the unsafe write and does not protect it.
4. Q4 / Step 4: The sink is line 95: `buff4[size3]='c';`. This is dangerous because `buff4` was allocated with exactly `size3` bytes at line 86, so valid positive indexes would be `0` through `size3 - 1`; writing index `size3` is a one-past-the-end heap write. If `size3` is zero or negative, the write is also invalid: `malloc(0)` gives no writable byte at index 0, and a negative `size3` used as an array index writes before the returned pointer.
5. Q5 / Step 5: No framework or library protection is visible. Standard C `malloc` does not bounds-check indexed writes, and `buff4[size3]='c';` at line 95 performs raw pointer arithmetic and memory write with no automatic protection.
6. Q6 / Step 6: Based on the provided caller, the code is triggered by running the program with a command-line filename argument: `ProcessImage(argv[1])`. An attacker would need the ability to provide or influence the input file processed by the program. No authentication or privilege checks are visible in the provided context.
7. Q7 / Step 7: If an attacker controls the input file contents, they can influence `img.width` and `img.height`, which determine `size3`. The concrete impact is heap memory corruption via out-of-bounds write at line 95, which can cause denial of service and may potentially lead to arbitrary code execution depending on allocator/runtime conditions. There is also a possible division-by-zero at line 82, but the flagged sink is the heap out-of-bounds write at line 95.
8. Q8 / Step 8: The weakest link is the absence of bounds validation before using `size3` as both the allocation size and the write index. Allocating `malloc(size3)` at line 86 and then writing `buff4[size3]` at line 95 is inherently off-by-one for positive `size3`, and no visible defense prevents the file-controlled dimensions from reaching that sink.
