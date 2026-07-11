# cpp/suspicious-sizeof @ practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10

**Verdict:** FP · **Confidence:** High (0.91) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The CodeQL pattern is real: line 10 applies `sizeof` to pointer parameter `ages` declared on line 8. However, the only visible use of that value is console output at line 10, and the function body has no other paths or memory-sensitive uses, so the finding is a correctness warning rather than an exploitable security vulnerability. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0: The flagged line is present at line 10: `std::cout << sizeof(ages) << '\n';`. The rule-described construct is present because `ages` is declared as `const int * ages` at line 8, so `sizeof(ages)` evaluates to the size of the pointer type.
2. Q1: No potentially dangerous attacker-controlled data source is visible. In the provided caller context, `ages` is a fixed local array initialized in `main` as `int ages[] = { 15, 30, 60 };`, then passed to `decay(ages)`. Inside the shown function, the only parameter is `const int * ages` at line 8.
3. Q2: Data flow: fixed local array `ages` in caller `main` → passed to `decay(ages)` in caller context → received as pointer parameter `const int * ages` at line 8 → `sizeof(ages)` computed at line 10 → result written to `std::cout` at line 10.
4. Q3: No validation, sanitization, or encoding is applied at lines 8-10. The relevant safety mechanism is not input sanitization; it is that the value is only used as an output value to `std::cout` on line 10, not as a size for allocation, copy, indexing, or memory access.
5. Q4: The sink is line 10: `std::cout << sizeof(ages) << '\n';`. The suspicious operation is `sizeof` on a pointer parameter. The operation would become dangerous if the pointer-size result were used for memory sizing, copying, bounds checking, or indexing, but the provided code only prints it.
6. Q5: No framework protection is relevant. The applicable C++ language/library behavior is visible at line 10: `sizeof(ages)` computes a `size_t` value based on the static type of `ages`, and `std::cout << ...` outputs that value.
7. Q6: No attacker privilege level or authentication state is visible. The provided caller context shows a direct local call from `main`, not an externally reachable interface.
8. Q7: No concrete security impact is visible. Even if the pointed-to array contents were attacker-controlled, `sizeof(ages)` at line 10 depends on the pointer type from line 8, not the pointed-to contents. The result is only printed, so no RCE, data theft, privilege escalation, DoS, buffer overflow, or out-of-bounds access is demonstrated.
9. Q8: The weakest link is a likely correctness misunderstanding: line 10 prints the pointer size rather than the array length or byte size. However, the defense against a security impact is complete in the shown function because the suspicious value is not used for any memory-sensitive operation.
10. (a) Specific observed defense: line 10 sends the `sizeof(ages)` result only to `std::cout` via `std::cout << sizeof(ages) << '\n';`. The exact mechanism is benign use of the computed pointer-size value as console output, not as a memory size, allocation size, copy length, loop bound, or array index.
11. (b) Coverage of all reachable paths: the body of `decay` shown at lines 8-13 contains only this executable statement at line 10. There are no branches, loops, alternative sinks, or later uses of the `sizeof(ages)` result in the provided function. Therefore every visible path to the flagged expression ends in printing only.
12. (c) Why SAST flagged it: `cpp/suspicious-sizeof` / CWE-467 looks for `sizeof` applied to a pointer where the programmer may have intended the size of the pointed-to object or original array. That pattern is genuinely present because `ages` is a pointer parameter at line 8 and `sizeof(ages)` appears at line 10. The cited defense does not check whether `sizeof` is applied to a pointer; instead, it shows that this specific flagged use is security-benign because the result is only printed.
