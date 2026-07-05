# cpp/invalid-pointer-deref @ imgRead.c:95

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The reported invalid pointer dereference/out-of-bounds write is directly present: buff4 is allocated with size3 bytes at line 86 and then written at index size3 at line 95, which is one byte past the allocation for any successful positive-size allocation. No visible validation or bounds check prevents attacker-controlled file data from influencing size3 and reaching the sink.

## Data flow

attacker-controlled argv[1] in main → fopen(filename, "r") in ProcessImage → fread(&img, sizeof(img), 1, fp) populates img from file → img.width/img.height compute size3 → malloc(size3) at line 86 returns buff4 → buff4[size3] = 'c' at line 95 performs one-past-end heap write

## Answers

1. Step 1: The potentially dangerous data originates from an attacker-supplied file path passed as argv[1] to ProcessImage in main (pre-fetched caller context), then file contents are read with fread(&img, sizeof(img), 1, fp) inside ProcessImage. The relevant fields are img.width, img.height, and img.data, which come from the file contents. Exact source-code line numbers for main/fread are not visible in the provided context, but CodeQL identifies malloc at line 86 and the sink at line 95.
2. Step 2: Data flow: argv[1] is passed to ProcessImage in main → filename is opened with fopen(filename, "r") in ProcessImage → fread populates struct Image img from the file → img.width and img.height are used to compute int size3 = img.width / img.height → size3 is passed to malloc at line 86 as malloc(size3), producing buff4 → size3 is then reused as an array index at line 95 in buff4[size3] = 'c'.
3. Step 3: No validation, sanitization, or bounds checking is visible for img.width, img.height, size3, or buff4. There is no check that img.height is nonzero before division, no check that size3 is positive, no check that malloc succeeded, and no check that index size3 is within the allocated range before line 95.
4. Step 4: The sink is the write at line 95: buff4[size3] = 'c'. This is dangerous because buff4 was allocated with malloc(size3) at line 86, so valid indexes are 0 through size3 - 1 for a positive size3 allocation. Writing buff4[size3] is a one-past-the-end heap write.
5. Step 5: No framework or library-level protection is visible. malloc does not add C-level bounds checking, and raw pointer indexing in C does not enforce allocation bounds. Not visible in provided context: any allocator hardening or runtime sanitizer configuration, and such mechanisms are not an adequate source-code defense here.
6. Step 6: Based on the provided caller, an attacker only needs the ability to supply the input file path argv[1] to the program and control the contents of that file. No authentication or privilege checks are visible in the provided context.
7. Step 7: If an attacker controls the file contents, they can influence size3 through img.width and img.height and trigger a heap out-of-bounds write at line 95. Concrete impacts include memory corruption, denial of service, and potentially code execution depending on allocator/runtime conditions.
8. Step 8: The weakest link is the absence of any bounds check between allocation and indexed write: malloc(size3) at line 86 is followed by buff4[size3] = 'c' at line 95. Because the index equals the allocation size, the write is outside the allocated object for any successful positive-size allocation.
