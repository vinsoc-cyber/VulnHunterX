# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line is present and exactly reads `char OOBR_heap = buff4[size3];` at line 91, which is an array access on a heap buffer allocated with malloc(size3) at line 86. Since C valid indexes for a size3-byte allocation are 0 through size3 - 1 and no visible validation prevents line 91, the flagged sink is a real off-by-one out-of-bounds heap read.

## Data flow

file contents read by fread into img (line 42) → img.width/img.height compute size3 (line 82) → malloc(size3) assigns buff4 (line 86) → buff4[size3] read (line 91)

## Answers

1. Step 1: The ultimate attacker-controlled data originates from a file selected via command-line argument argv[1] in main, which is passed to ProcessImage and opened at line 33. The file contents are read directly into struct Image img by fread at line 42, so img.width and img.height used later are file-controlled.
2. Step 2: Data flow: argv[1] in main → filename parameter to ProcessImage at line 29 → fopen(filename, "r") at line 33 → fread(&img, sizeof(img), 1, fp) at line 42 populates img from file → img.width and img.height are used to compute size3 at line 82 as img.width / img.height → size3 is used as the allocation size in malloc(size3) at line 86 assigning buff4 → buff4 is read at index size3 on line 91.
3. Step 3: No validation, sanitization, or bounds checking is visible for img.width, img.height, size3, or buff4. There is no check that img.height is nonzero before division at line 82, no check that size3 is positive or within a safe range before malloc at line 86, no check that malloc succeeded, and no check that index size3 is less than the allocated size before line 91.
4. Step 4: The sink is line 91: `char OOBR_heap = buff4[size3];`. This is dangerous because buff4 was allocated with exactly size3 bytes at line 86, making valid indexes 0 through size3 - 1 for positive size3. Accessing buff4[size3] reads one byte past the allocated heap buffer.
5. Step 5: No framework or library automatic protection is visible. malloc at line 86 only allocates memory; it does not make buff4[size3] valid. C array indexing provides no bounds checking.
6. Step 6: Based on the provided caller, an attacker needs the ability to invoke the program with a chosen filename via argv[1] and control the contents of that file. Authentication or privilege restrictions are not visible in the provided context.
7. Step 7: The concrete security impact is out-of-bounds heap read, potentially causing information disclosure or denial of service through invalid memory access. Related heap corruption may also occur earlier at line 87 if sizeof(img.data) exceeds size3, but the flagged sink itself is an out-of-bounds read.
8. Step 8: The weakest link is the complete absence of bounds validation tying the allocation size and index use together: size3 is used both as malloc size at line 86 and then as an index at line 91, guaranteeing an off-by-one out-of-bounds read for positive size3.
