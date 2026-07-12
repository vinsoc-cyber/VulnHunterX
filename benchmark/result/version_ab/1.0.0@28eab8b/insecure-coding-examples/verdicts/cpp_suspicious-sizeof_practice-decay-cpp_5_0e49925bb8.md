# cpp/suspicious-sizeof @ practice/decay.cpp:5

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The CodeQL pattern is real: line 5 applies `sizeof` to pointer parameter `ages` from line 3. However, the only visible use of the resulting pointer-size value is output via `std::cout` on line 5, and the function has no alternate paths or memory operations, so this is a correctness warning but not an exploitable memory-safety vulnerability in the provided context. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: line 5 uses `sizeof(ages)` only as an argument to `std::cout << ... << '\n'`: `std::cout << sizeof(ages) << '\n';`. The concrete mechanism preventing exploitation is that the suspicious size value is only printed; it is not used in a memory allocation, buffer copy, pointer arithmetic, array indexing, bounds check, or dereference.
2. (b) Coverage of all reachable paths: the entire function body shown is lines 3-8, with no branches, loops, callbacks, or alternate paths. The only reachable operation involving `ages` after entry at line 3 is the output statement on line 5. Therefore every visible path to the flagged sink ends in printing the value only.
3. (c) Why SAST flagged it: CodeQL rule `cpp/suspicious-sizeof` / CWE-467 looks for `sizeof` applied to a pointer expression where the programmer may have intended the size of the pointed-to object or original array. That pattern is present: `ages` is declared as `const int * ages` on line 3, and line 5 computes `sizeof(ages)`, which is the pointer type size. The cited defense does not make `sizeof(ages)` compute the array size; instead, it makes the finding non-exploitable because the result is only printed on line 5.
4. Original Step 1: The value originates from parameter `ages` declared on line 3. The pre-fetched caller shows it is passed from a local fixed array initialized with constants in `main`; no user, file, network, or database source is visible.
5. Original Step 2: Data flow is caller local array `ages` → call `decay(ages)` → pointer parameter `const int * ages` on line 3 → `sizeof(ages)` on line 5 → `std::cout` output on line 5.
6. Original Step 3: No validation or sanitization appears on lines 3-8. For this rule, the relevant visible mitigating fact is not sanitization but that the computed pointer-size value is not used in a dangerous memory operation.
7. Original Step 4: The sink is line 5, `std::cout << sizeof(ages) << '\n';`. The operation is suspicious because `sizeof` is applied to a pointer, but it is not dangerous here because it only outputs the numeric size.
8. Original Step 5: No framework or library protection is involved. The relevant C++ behavior is that `sizeof(ages)` computes the size of the pointer type, and `std::cout` only prints that value.
9. Original Step 6: The pre-fetched caller shows `main` invokes `decay(ages)`. No authentication or privilege context is visible, but no attacker-controlled input is visible either.
10. Original Step 7: The concrete security impact from the flagged line is none in the provided context: the pointer is not dereferenced, copied from, copied to, indexed, or used to size a buffer; only the pointer type size is printed.
11. Original Step 8: The weakest link is a correctness issue: line 5 likely prints pointer size rather than array size. However, no security-relevant weak link exists at the flagged sink because the value is not used for memory management or memory access.
