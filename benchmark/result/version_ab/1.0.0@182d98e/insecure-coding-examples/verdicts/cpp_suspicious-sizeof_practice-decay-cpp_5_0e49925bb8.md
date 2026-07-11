# cpp/suspicious-sizeof @ practice/decay.cpp:5

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and contains the exact suspicious construct: `sizeof(ages)` on line 5, where `ages` is a pointer parameter from line 3. CodeQL correctly reports a suspicious `sizeof(pointer)` pattern, but in this provided code the result is only printed on line 5 and is not used for allocation, copying, indexing, or bounds checking, so the flagged sink is harmless rather than exploitable. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense / benign mechanism: line 5 is exactly `std::cout << sizeof(ages) << '\n';`. The `sizeof(ages)` value is only inserted into `std::cout`; it is not used as a length for allocation, `memcpy`, `memmove`, `read`, `write`, indexing, loop bounds, or pointer arithmetic. The relevant safety mechanism is the absence of a dangerous memory-use sink on the flagged path, visible directly on line 5.
2. (b) Coverage of all reachable paths: the provided function `decay` has only one executable statement, line 5. The parameter is declared on line 3 as `const int * ages`, and every visible path through `decay` reaches only the print statement on line 5. There are no branches, assignments, calls using the computed size as a buffer length, or later uses of the `sizeof(ages)` result in the provided function.
3. (c) Why SAST flagged it: CodeQL rule `cpp/suspicious-sizeof` / CWE-467 looks for `sizeof` applied to a pointer where the programmer may have intended the size of the pointed-to object or original array. The rule correctly matches line 5 because `ages` is declared as `const int * ages` on line 3, so `sizeof(ages)` evaluates to the size of the pointer type. The benign mechanism cited above does not prove `sizeof(ages)` is semantically intended; it proves the flagged expression is not used in a security-sensitive memory operation in the visible code.
