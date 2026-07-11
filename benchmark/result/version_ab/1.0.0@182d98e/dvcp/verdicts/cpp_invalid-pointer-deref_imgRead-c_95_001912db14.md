# cpp/invalid-pointer-deref @ imgRead.c:95

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 95 writes to `buff4[size3]`, while `buff4` was allocated with exactly `size3` bytes at line 86. Since C arrays are zero-indexed and no validation or bounds check is visible, this is a one-past-the-end heap write on a reachable path after reading attacker-influenced file data.

## Data flow

file selected by argv[1] in main → fopen(filename) at line 33 → fread(&img,sizeof(img),1,fp) at line 42 → img.width/img.height used to compute size3 at line 82 → malloc(size3) assigns buff4 at line 86 → out-of-bounds write buff4[size3]='c' at line 95

## Answers

1. Step 0 / locating flagged line: The flagged line is present at line 95 and its exact text is `buff4[size3]='c';`. The construct described by the rule is present: an indexed write through pointer `buff4` using index `size3`, where `buff4` was allocated with `malloc(size3)` at line 86.
2. Step 1: The potentially dangerous data ultimately originates from a file selected by command-line argument `argv[1]` in `main`, passed to `ProcessImage(argv[1])`, then opened at line 33 and read into `img` with `fread(&img,sizeof(img),1,fp)` at line 42. The attacker-controlled fields are `img.width` and `img.height`, which influence `size3` at line 82.
3. Step 2: Data flow: `argv[1]` is passed to `ProcessImage` by `main`; `filename` is opened with `fopen(filename,"r")` at line 33; file contents are read into `img` at line 42; `img.width` and `img.height` are used to compute `size3 = img.width/img.height` at line 82; `size3` is used as the allocation size in `malloc(size3)` at line 86, producing `buff4`; then the same `size3` is used as the index in `buff4[size3]='c';` at line 95.
4. Step 3: No validation, sanitization, or bounds checking is visible for `img.width`, `img.height`, `size3`, or `buff4`. There is no check that `img.height` is nonzero before division at line 82, no check that `size3` is positive or within a safe range before `malloc(size3)` at line 86, no check that `malloc` succeeded, and no check that index `size3` is less than the allocated size before line 95.
5. Step 4: The sink is line 95, `buff4[size3]='c';`. This is dangerous because `buff4` was allocated with exactly `size3` bytes at line 86, so valid byte indices would be `0` through `size3 - 1`; writing to `buff4[size3]` is a one-past-the-end heap write when `size3` is positive.
6. Step 5: No framework or library automatic protection is visible. `malloc` at line 86 only allocates memory and does not protect against out-of-bounds indexing. C performs no automatic bounds checking for `buff4[size3]` at line 95.
7. Step 6: The provided caller shows this is a command-line program. An attacker would need the ability to invoke the program with a chosen filename and provide/control the file contents read at line 42. No authentication or privilege boundary is visible in the provided context.
8. Step 7: The concrete security impact is heap memory corruption from an out-of-bounds write at line 95, potentially causing denial of service or possibly arbitrary code execution depending on allocator behavior and exploitability. There is also a potential earlier divide-by-zero at line 82 and heap overflow at line 87, but the flagged sink itself is the heap out-of-bounds write at line 95.
9. Step 8: The weakest link is the absence of any bounds check between allocation and indexing: `malloc(size3)` at line 86 allocates `size3` bytes, but line 95 writes to index `size3`, which is outside the allocated object. No visible defense prevents this path.
