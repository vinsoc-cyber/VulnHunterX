# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** NMD · **Confidence:** Medium (0.62) · **Truth:** not-real · **Grade:** abstain · **Iterations:** 2

## Reasoning

The prior False Positive verdict cannot be justified because no specific visible defense protects the unsafe cast at line 16. However, the provided snippet also does not show the definitions of `Spiderman` and `Ironman` or any subsequent use of `tony3`, so the exploitability and concrete security impact of the type-confused pointer cannot be fully determined from this context alone. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line verification: The flagged line is present at line 16: `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. The construct described by the rule is present: a `reinterpret_cast` from `Spiderman *` to `Ironman *`.
2. Step 1: The potentially dangerous value originates from local heap allocation, not visible external input: `Spiderman * peter = new Spiderman;` on line 12. No user input, file, network, or database source is visible in the provided code.
3. Step 2: Data flow is: `new Spiderman` creates an object on line 12 → pointer stored in `peter` on line 12 → `peter` is cast to `Ironman *` using a C-style cast on line 13 → the flagged flow casts `peter` to `Ironman *` using `reinterpret_cast` on line 16. Line 18 separately attempts `dynamic_cast<Ironman *>(peter)`, but that does not validate or protect the line-16 cast.
4. Step 3: No validation, sanitization, or type-safety check is applied before the flagged cast on line 16. A potentially relevant check would be a successful `dynamic_cast` result tested before use, but the only `dynamic_cast` appears later on line 18 and is unrelated to `tony3` on line 16.
5. Step 4: The sink is line 16: `reinterpret_cast<Ironman *>(peter)`. The dangerous operation is forcing a pointer to a `Spiderman` object to be treated as an `Ironman *`, which can create type confusion if the resulting pointer is used as an `Ironman` object.
6. Step 5: No framework or library automatic protection is visible. This is raw C++ pointer casting, and `reinterpret_cast` does not provide runtime type checking.
7. Step 6: The visible code is `main` and has no visible authentication or attacker-controlled trigger. The path to line 16 appears unconditionally reachable once `main` executes, but attacker reachability is not visible in the provided context.
8. Step 7: If the type-confused pointer were dereferenced, used for virtual dispatch, field access, or deletion, the impact could include undefined behavior, crash/DoS, memory corruption, or potentially code execution. In the provided snippet, no such use of `tony3` after line 16 is visible.
9. Step 8: The weakest link is the unchecked `reinterpret_cast` on line 16. However, the provided context does not show the class definitions for `Spiderman` and `Ironman`, nor does it show any use of `tony3` that would demonstrate concrete exploitation.
10. Verification (a): I cannot enumerate a specific defense with an exact line number. No bounds check, type check, successful `dynamic_cast` guard, sanitizer, or other protective mechanism is applied to the value before the sink at line 16.
11. Verification (b): Because no defense is visible, there is no defense that can be shown to cover all reachable paths to line 16. The path from line 12 to line 16 is direct and unconditional in the provided code.
12. Verification (c): The SAST rule `cpp/type-confusion` looks for invalid or unsafe conversions between incompatible C++ types. It likely flagged line 16 because `reinterpret_cast<Ironman *>(peter)` forcibly converts a `Spiderman *` into an `Ironman *`. Since no visible defense checks that `peter` actually points to an `Ironman` or compatible subtype before line 16, there is no cited defense that addresses the rule condition.

## Context needed

- struct:Spiderman
- struct:Ironman
