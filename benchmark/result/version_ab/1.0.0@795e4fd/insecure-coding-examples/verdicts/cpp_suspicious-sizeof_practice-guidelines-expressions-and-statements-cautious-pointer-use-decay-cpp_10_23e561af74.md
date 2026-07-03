# cpp/suspicious-sizeof @ practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10

**Verdict:** FP · **Confidence:** Medium (0.78) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The CodeQL pattern is real because line 10 applies `sizeof` to the pointer parameter declared on line 8. However, the only visible use of the computed value is scalar output via `std::cout` on line 10, and the function has no alternate path where that value controls allocation, copying, indexing, or bounds. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0: The flagged line is present at line 10: `std::cout << sizeof(ages) << '\n';`. The rule construct is present: `ages` is declared as `const int * ages` on line 8, so `sizeof(ages)` on line 10 evaluates to the size of the pointer type.
2. (a) Specific observed defense: line 10 uses the result only as an argument to `std::cout << ...`, i.e. formatted output of a scalar `sizeof` value. There is no visible use of `sizeof(ages)` for allocation, `memcpy`, `memset`, indexing, loop bounds, pointer arithmetic, or buffer-size calculation.
3. (b) Coverage of all reachable paths: the provided body of `decay` consists only of the statement on line 10, with no branches or alternate paths between entry at line 8 and function exit at line 13. Therefore every reachable path involving `sizeof(ages)` ends in printing the value to `std::cout` on line 10.
4. (c) Why SAST flagged it: the `cpp/suspicious-sizeof` / CWE-467 rule looks for `sizeof` applied to a pointer where the programmer may have intended the size of the pointed-to object or original array. That pattern genuinely exists at line 10 because `ages` is a pointer parameter from line 8. The observed defense does not check or change that fact; rather, it prevents the pointer-size value from reaching a memory-safety-sensitive sink in the provided code.
5. Step 1: No dangerous external source is visible. In the pre-fetched caller, `ages` originates from a local fixed array `int ages[] = { 15, 30, 60 };` in `main`, then is passed as `decay(ages)`. No user input, file, network, or database input is shown.
6. Step 2: Data flow is: local array `ages` in caller `main` → array-to-pointer decay at `decay(ages)` → parameter `const int * ages` on line 8 → `sizeof(ages)` on line 10 → scalar value printed via `std::cout` on line 10.
7. Step 3: No validation, sanitization, or encoding is applied. For this rule, the relevant issue is not tainted contents but applying `sizeof` to a pointer. The provided code does not correct that calculation, but it also does not use the result in a dangerous memory operation.
8. Step 4: The sink for the computed value is `std::cout` on line 10. The suspicious operation is `sizeof(ages)` on line 10; it computes pointer size rather than array size. In this context, the operation is not used unsafely for memory management.
9. Step 5: No framework/library automatic protection is relevant. The C++ language behavior itself explains the finding: since `ages` is a pointer parameter on line 8, `sizeof(ages)` on line 10 yields pointer size.
10. Step 6: No attacker privilege level is visible or applicable. The only shown caller passes a locally initialized fixed array to `decay`; no attacker-controlled invocation is shown.
11. Step 7: No concrete security impact is visible in the provided code. The value is printed only; it is not used to under-allocate, over-copy, bypass bounds checks, or access memory.
12. Step 8: The weakest link is the suspicious pointer-size computation at line 10. However, all visible paths use the value only for output, so the provided code does not show an exploitable CWE-467 memory-safety issue.
