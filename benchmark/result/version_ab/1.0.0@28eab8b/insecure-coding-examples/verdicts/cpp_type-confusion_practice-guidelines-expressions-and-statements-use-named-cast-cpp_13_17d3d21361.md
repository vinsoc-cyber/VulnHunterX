# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** TP · **Confidence:** Medium (0.8) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

Line 13 contains the same unsafe type-confusion construct as the confirmed sibling: the same `Spiderman * peter` from line 12 is converted to `Ironman *` with no visible type check or other defense. Because this line adds no material protection and is reached before the sibling in `main`, the same type-confusion consequence applies. [second-opinion pass: sibling-consistency challenge]

## Answers

1. Step 0: The flagged line is present at line 13: `Ironman * tony1 = (Ironman *)peter;`. The construct described by the rule is present: a `Spiderman *` value, `peter`, is converted to `Ironman *` using a C-style cast.
2. Step 1 / vulnerability class: The rule is `cpp/type-confusion`, CWE-843. The issue is invalid pointer reinterpretation between incompatible C++ object types, here from `Spiderman *` to `Ironman *` at line 13.
3. (a) This line is materially the same construct as the sibling at line 16: line 13 performs `Ironman * tony1 = (Ironman *)peter;`, while line 16 performs `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. Both use the same source pointer `peter`, allocated as `Spiderman *` at line 12, and both convert it to `Ironman *`. The only material syntactic difference is C-style cast versus explicit `reinterpret_cast`; both bypass type safety.
4. (b) This line adds no real defense. There is no validation, sanitization, allowlist, canonicalization, runtime type check, or safe `dynamic_cast`-with-check before line 13. The source remains `new Spiderman` assigned to `peter` at line 12, and line 13 directly casts it to `Ironman *`.
5. (c) This sink is not shown to be less reachable than the sibling. Both are in `main` starting at line 11, both use `peter` from line 12, and both are executed sequentially in the visible code unless the program terminates earlier, which is not shown before line 13. Line 13 is reached before the sibling line 16.
6. Step 2: Data flow is: line 12 allocates a `Spiderman` object using `new Spiderman`; line 12 stores that pointer in `Spiderman * peter`; line 13 reads `peter`; line 13 casts it to `Ironman *`; line 13 stores the result in `tony1`.
7. Step 3: No validation, sanitization, encoding, or runtime type verification is visible between line 12 and line 13.
8. Step 4: The sink is the invalid type conversion at line 13. The dangerous operation is treating a `Spiderman *` as an `Ironman *`, creating a type-confused pointer.
9. Step 5: No framework or library protection is involved. This is raw C++ pointer casting, and a C-style cast provides no automatic runtime type safety.
10. Step 6: The code is in `main` at line 11. No authentication or privilege boundary is visible in the provided context.
11. Step 7: The concrete impact of this class is undefined behavior if the resulting pointer is used as an `Ironman *`, potentially causing memory corruption, denial of service, or code execution depending on subsequent use. The sibling finding in the same file establishes this consequence for the same construct.
12. Step 8: The weakest link is the unchecked cast at line 13. There is no visible defense that distinguishes this line from the confirmed sibling.
