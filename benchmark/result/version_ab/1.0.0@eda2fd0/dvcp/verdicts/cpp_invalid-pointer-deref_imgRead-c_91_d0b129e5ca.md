# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged construct is an invalid pointer/array dereference: buff4 is allocated with size3 bytes at line 86 and then read at index size3 at line 91, which is one past the valid range. No validation, bounds check, or C/library protection is visible on this path.

## Data flow

attacker-controlled file contents read by fread into img → img.width/img.height used to compute size3 → malloc(size3) at line 86 assigns buff4 → buff4[size3] read at line 91

## Answers

1. Step 1: The dangerous data ultimately originates from an attacker-supplied file path passed as argv[1] in main, then opened by ProcessImage via fopen(filename, "r") (main calls ProcessImage(argv[1]); ProcessImage reads file records with fread(&img, sizeof(img), 1, fp)). The actual values img.width, img.height, and img.data come from the file contents read into img.
2. Step 2: Data flow: argv[1] in main → ProcessImage(filename) → fopen(filename, "r") → fread(&img, sizeof(img), 1, fp) populates struct Image fields → img.width and img.height are used to compute int size3 = img.width / img.height → size3 is passed to malloc at line 86 as malloc(size3) assigning buff4 → buff4 is indexed using the same size3 at line 91 as buff4[size3].
3. Step 3: No validation, sanitization, or bounds checking is visible. There is no check that img.height is nonzero before division, no check that size3 is positive, no check that malloc succeeded, and no check that the index size3 is less than the allocated size before buff4[size3] at line 91.
4. Step 4: The sink is the array access at line 91: char OOBR_heap = buff4[size3]. This is dangerous because buff4 was allocated with exactly size3 bytes at line 86, so valid indexes are 0 through size3 - 1. Accessing buff4[size3] reads one byte past the allocated heap buffer.
5. Step 5: No framework or library-level automatic protection is visible. malloc provides raw memory only and does not add C-level bounds checking. C array/pointer indexing also provides no automatic bounds enforcement.
6. Step 6: Based on the provided caller, an attacker needs the ability to supply the input filename/path to the program via argv[1] and control the contents of that file. No authentication or privilege checks are visible in the provided context.
7. Step 7: The concrete security impact for the flagged read is an out-of-bounds heap read, which can cause a crash/denial of service or potentially disclose adjacent heap memory. The same unchecked size is also used in nearby out-of-bounds writes, but the reported rule specifically concerns the invalid read at line 91.
8. Step 8: The weakest link is the absence of bounds validation between allocation and indexing: size3 derived from file-controlled img.width/img.height is used both as the allocation size at line 86 and as the index at line 91, guaranteeing a one-past-the-end access when malloc(size3) succeeds for a positive size3.
