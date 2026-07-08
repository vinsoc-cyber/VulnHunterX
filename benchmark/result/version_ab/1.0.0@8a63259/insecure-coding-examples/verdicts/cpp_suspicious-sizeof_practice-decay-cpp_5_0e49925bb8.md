# cpp/suspicious-sizeof @ practice/decay.cpp:5

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The reported CWE-467 construct is definitely present: line 5 applies `sizeof` to the pointer parameter declared on line 3. No visible defense prevents or corrects that computation, although the visible security impact is low because the value is only printed. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0: The flagged line is present at line 5: `std::cout << sizeof(ages) << '\n';`. The rule-described construct is present on that line: `ages` is declared as `const int * ages` on line 3, so `sizeof(ages)` evaluates to the size of the pointer type, not the size of the original array.
2. Step 1: No external dangerous data source is visible. The pre-fetched caller shows a fixed local array `int ages[] = { 15, 30, 60 };` passed to `decay(ages)`. The relevant issue is not tainted data but misuse of `sizeof` on a pointer parameter.
3. Step 2: Data/control flow is: fixed local array `ages` in `main` → call `decay(ages)` in the caller → parameter `const int * ages` on line 3 → `sizeof(ages)` on line 5 → stream insertion into `std::cout` on line 5.
4. Step 3: No validation, sanitization, encoding, or size check is visible. More importantly for CWE-467, there is no defense that converts the pointer back into an array size or passes an explicit element count.
5. Step 4: The sink for the reported rule is the `sizeof(ages)` expression on line 5. The unsafe/suspicious operation is applying `sizeof` to a pointer parameter, which produces pointer size rather than array size.
6. Step 5: No framework or library protection is visible. C++ language semantics guarantee that `sizeof(ages)` on line 5 evaluates to the size of `const int *`, because `ages` is a pointer parameter from line 3.
7. Step 6: Attacker privilege or authentication state is not visible in the provided context. The shown caller is local `main` using a fixed array, so no attacker-triggerable path is demonstrated.
8. Step 7: Concrete security impact is not demonstrated by the visible code because the pointer-size result is only printed on line 5. However, the specific CodeQL finding is still correct that the expression evaluates to pointer size.
9. Step 8: The weakest link is the use of `sizeof(ages)` on line 5 after `ages` has decayed/been received as `const int *` on line 3. No visible defense checks or prevents that condition.
10. (a) Specific defense observed: No complete defense against the reported rule is present. Line 5 only streams the value to `std::cout`; that limits visible security impact, but it does not prevent `sizeof(ages)` from evaluating to pointer size.
11. (b) Coverage of all reachable paths: The provided function has only one executable statement, line 5, so every visible path through `decay` reaches `sizeof(ages)`. There is no branch or guard that avoids the flagged expression.
12. (c) Why SAST flagged it: `cpp/suspicious-sizeof` / CWE-467 looks for use of `sizeof` on a pointer where an array/object size may have been intended. It flagged line 5 because `ages` is a `const int *` parameter from line 3. The only previously cited mitigating fact, that the result is printed, does not check or correct the pointer-size computation.
