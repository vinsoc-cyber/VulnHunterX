# cpp/suspicious-sizeof @ practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10

**Verdict:** FP · **Confidence:** Medium (0.78) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The CodeQL pattern is real: line 10 computes the size of the pointer parameter declared on line 8. However, the only visible use of that value is printing it with `std::cout` on line 10, and there is no visible memory allocation, copy, indexing, or bounds operation that would make CWE-467 exploitable. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0: The flagged line is present at line 10: `std::cout << sizeof(ages) << '\n';`. The rule construct is genuinely present: `ages` is declared as `const int * ages` on line 8, so `sizeof(ages)` evaluates to the size of the pointer type.
2. Step 1: No attacker-controlled source is visible. The pre-fetched caller initializes `int ages[] = { 15, 30, 60 };` locally and passes it to `decay(ages)`. In `decay`, the parameter is `const int * ages` on line 8.
3. Step 2: Data flow is: local caller array `ages` → call `decay(ages)` in the pre-fetched caller → pointer parameter `const int * ages` on line 8 → `sizeof(ages)` on line 10 → printed using `std::cout` on line 10.
4. Step 3: No validation, sanitization, or encoding is applied on lines 8-10. For CWE-467, such validation would not change the result anyway because `sizeof(ages)` depends on the static type of `ages`, not on the contents or value of the pointer.
5. Step 4: The sink for the reported rule is `sizeof(ages)` on line 10. The suspicious operation is applying `sizeof` to a pointer parameter rather than to an actual array object. The potentially dangerous security pattern would be using that pointer-size result for allocation, copying, indexing, or bounds calculation; that is not visible here.
6. Step 5: No framework protection is relevant. The relevant C++/standard-library behavior visible here is that line 10 passes the resulting integer value to `std::cout`; this prints the value and does not use it as a memory size for copying or allocation.
7. Step 6: The privilege or authentication state needed to trigger this code path is not visible. The only provided caller is a local `main` function, with no network, file, database, or user-input path shown.
8. Step 7: No concrete security impact is visible in the provided code. The expression on line 10 may be logically misleading, but the value is only printed; there is no visible RCE, data theft, privilege escalation, out-of-bounds access, or DoS path.
9. Step 8: The weakest link is the misleading expression `sizeof(ages)` on line 10. However, the observed limiting mechanism is also on line 10: the result flows only to `std::cout`, not to a memory-sensitive operation.
10. (a) Specific defense observed: line 10 uses the `sizeof(ages)` result only as an operand to `std::cout << ...`, i.e. as a value to be printed. There is no allocation, `memcpy`, array indexing, loop bound, or buffer-size calculation in the provided function body.
11. (b) Coverage of all reachable paths: the provided `decay` body contains only one executable statement, line 10. Therefore every visible path through `decay` reaches the same sink, and the computed pointer-size value has no other visible use before the function returns at line 13.
12. (c) Why CodeQL flagged it: `cpp/suspicious-sizeof` / CWE-467 looks for `sizeof` applied to an expression of pointer type where array size may have been intended. That pattern is present because `ages` is `const int *` on line 8 and `sizeof(ages)` is used on line 10. The cited defense is not a check that changes `sizeof` behavior; it only prevents a security-relevant consequence because the value is printed rather than used for memory sizing.
