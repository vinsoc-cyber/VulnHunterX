# cpp/suspicious-sizeof @ practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The exact construct reported by `cpp/suspicious-sizeof` is present: `sizeof(ages)` at line 3 is applied to `ages`, which is a `const int *` parameter at line 1. I cannot cite a concrete defense that prevents this expression from evaluating to pointer size, although the snippet does not show a downstream memory-corruption impact because the value is only printed. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 1: No external attacker-controlled source is visible. The value originates as local fixed array `int ages[] = { 15, 30, 60 };` in `main` (caller line 2), then is passed to `decay(ages)` (caller line 9).
2. Step 2: Data flow is: local array `ages` in `main` (caller line 2) → passed to `decay(ages)` (caller line 9), where array-to-pointer decay occurs → received as parameter `const int * ages` in `decay` (line 1) → used in `sizeof(ages)` (line 3).
3. Step 3: No validation, sanitization, encoding, bounds check, or type-preserving mechanism is visible. There is no line that preserves the array extent after passing it into `decay`; at line 1 the parameter type is already `const int *`, and line 3 applies `sizeof` to that pointer.
4. Step 4: The sink is `sizeof(ages)` inside `std::cout << sizeof(ages) << '\n';` at line 3. The unsafe/suspicious operation for CWE-467 is applying `sizeof` to a pointer parameter, which evaluates to the size of the pointer type rather than the size of the original array.
5. Step 5: No framework or library protection is visible or relevant. `std::cout` at line 3 only prints the result; it does not validate that `sizeof(ages)` reflects the original array size.
6. Step 6: Based on the provided caller, no authentication or privilege level is visible. The path is directly reachable from `main` via `decay(ages)` at caller line 9.
7. Step 7: The concrete security impact is not demonstrated as memory corruption in this snippet because the pointer size is only printed at line 3. However, for the reported CWE-467 rule, the suspicious construct itself is present: the code computes the size of the pointer rather than the array.
8. Step 8: No complete defense chain exists for the reported issue. The weakest link is that `ages` has decayed to `const int *` at line 1, and `sizeof(ages)` at line 3 therefore cannot recover the original array size.
9. (a) Specific defense observed: None. There is no guard or mechanism in the provided code that prevents `sizeof(ages)` at line 3 from evaluating to the pointer size; the parameter is explicitly `const int * ages` at line 1.
10. (b) Coverage of all reachable paths: Since no defense is present, there is nothing that covers all reachable paths. The only shown path, `main` caller line 9 → `decay` line 1 → `sizeof(ages)` line 3, reaches the flagged expression directly.
11. (c) Why the SAST tool flagged this: The CodeQL rule `cpp/suspicious-sizeof`/CWE-467 looks for `sizeof` applied to a pointer where an array/object size may have been intended. That exact construct appears at line 3 because `ages` is declared as `const int *` at line 1. No cited defense checks or changes that fact.
