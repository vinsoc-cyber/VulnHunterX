# cpp/invalid-pointer-deref @ imgRead.c:95

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line is a heap write one past the allocated object: `buff4` is allocated with `size3` bytes at line 86 and then written at index `size3` at line 95. Since `size3` is derived from untrusted file data with no validation or bounds check, the path is reachable and exploitable as an out-of-bounds write.

## Data flow

file contents read by fread into img (line 42) → img.width/img.height used to compute size3 (line 82) → size3 used as malloc size for buff4 (line 86) → size3 reused as array index in buff4[size3] write (line 95)

## Answers

1. Flagged line 95 is present and reads exactly: `buff4[size3]='c';`. This is an indexed write through `buff4`, matching the invalid/out-of-bounds pointer dereference construct. The potentially dangerous data ultimately originates from the input file: `filename` is supplied from `argv[1]` in `main`, then opened at line 33, and file contents are read directly into `img` at line 42.
2. Data flow: `argv[1]` in `main` → `ProcessImage(argv[1])` → `fopen(filename, "r")` at line 33 → `fread(&img, sizeof(img), 1, fp)` at line 42 populates `img.width` and `img.height` → `size3 = img.width / img.height` at line 82 → `buff4 = malloc(size3)` at line 86 → `buff4[size3] = 'c'` at line 95.
3. No validation, sanitization, or bounds checking is visible. There is no check that `img.height` is nonzero before division at line 82, no check that `size3` is positive or within a safe range before `malloc(size3)` at line 86, no check that `malloc` succeeded, and no check that index `size3` is less than the allocated length before the write at line 95.
4. The sink is line 95: `buff4[size3]='c';`. The dangerous operation is writing to index `size3` of a heap buffer allocated with exactly `size3` bytes at line 86. For a valid positive allocation of `size3` bytes, valid indexes are `0` through `size3 - 1`, so `buff4[size3]` is one byte out of bounds.
5. No framework or library-level automatic protection is visible. `malloc` only allocates memory and does not add bounds checking for later pointer arithmetic or array indexing. C provides no automatic runtime bounds protection for `buff4[size3]`.
6. The provided caller shows `ProcessImage(argv[1])` is invoked from `main` using a command-line filename. An attacker would need the ability to cause the program to process an attacker-controlled file path or file contents. Authentication state is not visible in this standalone C context; from the shown code, no authentication or privilege gate is present.
7. Concrete impact is heap out-of-bounds write at line 95, which can cause memory corruption, denial of service, and potentially code execution depending on allocator behavior and runtime environment. The same attacker-controlled fields also influence allocation size and indexing through lines 82, 86, and 95.
8. The weakest link is the complete lack of bounds validation between attacker-controlled file fields and the heap write: `size3` is derived from untrusted `img.width` and `img.height` at line 82, used as the allocation size at line 86, and then used as an out-of-bounds index at line 95. No complete defense is visible.
