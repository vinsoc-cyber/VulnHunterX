# cpp/suspicious-sizeof @ practice/decay.cpp:5

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The CodeQL rule specifically flags `sizeof` applied to a pointer, and that construct is plainly present: `ages` is declared as `const int *` on line 1 and used in `sizeof(ages)` on flagged file line 5 / snippet line 3. No concrete defense is visible, although the shown impact is only an incorrect printed size rather than a directly exploitable memory-safety operation. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: None. There is no bounds check, replacement with `std::size`, template array-reference parameter, explicit length parameter, or other mechanism preventing `sizeof(ages)` from being applied to a pointer. The parameter is declared as `const int * ages` in `decay` line 1, and the flagged expression `sizeof(ages)` appears unguarded on flagged file line 5 / snippet line 3.
2. (b) Coverage of all reachable paths: No defense covers reachable paths. The sink is unconditional inside `decay`: execution of `decay` reaches `std::cout << sizeof(ages) << '\n';` on flagged file line 5 / snippet line 3. The visible caller invokes `decay(ages)` from `main` on caller line 10, after declaring a fixed array on caller line 3; that call decays the array to a pointer. No conditional guard or alternative safe path is visible.
3. (c) Why the SAST tool flagged this: The `cpp/suspicious-sizeof` / CWE-467 rule looks for `sizeof` applied to a pointer where the programmer may have intended the size of the pointed-to object or original array. That exact construct is present: `ages` is a `const int *` parameter on `decay` line 1, and `sizeof(ages)` on flagged file line 5 / snippet line 3 therefore evaluates to the size of the pointer type. There is no cited defense checking or preventing this condition.
4. Step 1: No external attacker-controlled source is visible. In the provided caller, `ages` originates as a fixed local array `int ages[] = { 15, 30, 60 };` on caller line 3.
5. Step 2: Data flow is fixed local array `ages` in `main` on caller line 3 → passed as `decay(ages)` on caller line 10, where it decays to a pointer → received as `const int * ages` in `decay` line 1 → used in `sizeof(ages)` on flagged file line 5 / snippet line 3.
6. Step 3: No validation, sanitization, encoding, or type-level protection is applied. The visible code does not preserve array extent, does not pass an element count, and does not use `std::size` inside `decay`.
7. Step 4: The sink is `sizeof(ages)` in `std::cout << sizeof(ages) << '\n';` on flagged file line 5 / snippet line 3. The unsafe/suspicious operation is computing the size of the pointer parameter rather than the size of the original array.
8. Step 5: No framework or library automatic protection is visible. `std::cout` only prints the resulting value and does not alter the semantics of `sizeof(ages)`.
9. Step 6: The visible trigger path is local execution of `main`; no authentication or privilege model is visible in the provided context.
10. Step 7: The concrete security impact is limited in the shown code because the incorrect size is only printed, not used for allocation, copying, indexing, or bounds checks. However, for the specific CodeQL rule, the suspicious pointer-size computation itself is real.
11. Step 8: The weakest link is the function signature `void decay(const int * ages)` on line 1 combined with `sizeof(ages)` on flagged file line 5 / snippet line 3; array size information has been lost due to pointer decay, and no visible defense restores or checks the intended extent.
