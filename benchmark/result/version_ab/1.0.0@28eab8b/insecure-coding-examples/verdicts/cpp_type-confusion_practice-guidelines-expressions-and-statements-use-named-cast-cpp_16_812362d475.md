# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

On re-verification, there is no concrete defense visible in the provided code: the flagged line 16 directly performs an unchecked `reinterpret_cast` from `Spiderman *` to `Ironman *`. The confidence is low because the snippet does not show a later dereference or attacker-controlled source, but the reported type-confusion pattern itself is present and undefended. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / location: The flagged line is present at line 16: `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. The construct described by the rule is present on that line: a `Spiderman *` value, `peter`, is converted to `Ironman *` using `reinterpret_cast`.
2. Step 1: The potentially dangerous data originates at line 12: `Spiderman * peter = new Spiderman;`. In the provided code, this is a local heap allocation, not visible user input, file input, network input, or database input.
3. Step 2: The data flow is: line 12 allocates a `Spiderman` object with `new Spiderman`; line 12 stores the resulting pointer in `Spiderman * peter`; line 16 passes `peter` into `reinterpret_cast<Ironman *>(peter)`; line 16 stores the converted pointer in `Ironman * tony3`.
4. Step 3: No validation, sanitization, type check, or safe cast is applied on the flagged path from line 12 to line 16. The only relevant operation on the flagged path is the unchecked `reinterpret_cast` at line 16.
5. Step 4: The sink is line 16: `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. The unsafe operation is treating a pointer to a `Spiderman` object as an `Ironman *`, which is the type-confusion pattern reported by CodeQL.
6. Step 5: No framework or library protection is visible in the provided code. This is standalone C++ pointer casting; there is no visible automatic runtime type protection around `reinterpret_cast` at line 16.
7. Step 6: The privilege level or authentication state needed to trigger this path is not visible in the provided context. The code is in `main` at line 11, but there is no visible external input or authentication boundary.
8. Step 7: If the invalidly converted pointer is later used as an `Ironman *`, the potential security impact could be undefined behavior, memory corruption, crash/DoS, or potentially code execution depending on object layouts and later use. The provided snippet does not show a dereference or later use of `tony3`, so exploitability beyond the invalid conversion itself is not fully demonstrated.
9. Step 8: The weakest link is the unchecked `reinterpret_cast` at line 16. There is no visible defense such as a valid inheritance relationship, runtime type check, or use of `dynamic_cast` on the flagged path.
10. Verification (a): I cannot enumerate a specific defense with line references. There is no visible defense before or at line 16; the line directly performs `reinterpret_cast<Ironman *>(peter)`.
11. Verification (b): Because no defense is visible, I cannot show that a defense covers all reachable paths to the sink. The only visible path to the flagged sink is line 12 `new Spiderman` / `peter` to line 16 `reinterpret_cast`, and that path has no guard.
12. Verification (c): CodeQL's `cpp/type-confusion` rule looks for invalid conversions between incompatible C++ types that may lead to type confusion. The flagged line 16 matches that pattern directly. No cited defense is checking compatibility at line 16; `reinterpret_cast` bypasses normal type safety.
