# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The flagged line is present and contains the invalid cast pattern reported by cpp/type-confusion, and there is no visible guard or runtime type check before the cast. Confidence is low because the snippet does not show subsequent use of `tony1`, so exploitability beyond the invalid conversion itself is not demonstrated. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Flagged line located at line 13: `Ironman * tony1 = (Ironman *)peter;`. The reported construct is present on that line: a C-style pointer cast from `Spiderman *` to `Ironman *`, matching the cpp/type-confusion finding.
2. Step 1: The potentially dangerous value originates at line 12 from local heap allocation: `Spiderman * peter = new Spiderman;`. No user input, file, network, or database source is visible in the provided context.
3. Step 2: Data flow is line 12 `new Spiderman` → line 12 assignment to `Spiderman * peter` → line 13 C-style cast `(Ironman *)peter` → line 13 assignment to `Ironman * tony1`. No additional assignments or function calls on this path are shown.
4. Step 3: No validation, sanitization, encoding, or runtime type check is applied before the flagged cast on line 13. The `dynamic_cast` on line 18 is a separate expression for `tony4` and does not protect `tony1` on line 13.
5. Step 4: The sink is the cast operation on line 13: `(Ironman *)peter`. The unsafe operation is treating a `Spiderman *` as an `Ironman *`, which is the type-confusion pattern reported by the rule.
6. Step 5: No framework or library protection is visible. This is raw C++ pointer allocation and casting on lines 12-13.
7. Step 6: Not visible in provided context. The code is in `main` at line 11, but no caller, command-line parsing, authentication boundary, or external trigger condition is shown.
8. Step 7: If the incorrectly typed pointer were later used, possible security impact could include undefined behavior, memory corruption, crash/DoS, or potentially code execution. In the provided snippet, no later dereference or method call through `tony1` is visible, but the invalid conversion itself is present.
9. Step 8: I cannot enumerate a concrete defense at the flagged path. There is no visible type check or safe cast guarding line 13. The weakest link is the unchecked C-style cast on line 13.
10. (a) Specific defense observed: none. There is no line before line 13 that checks `peter`'s dynamic type or otherwise proves it is safe to convert to `Ironman *`.
11. (b) Because no concrete defense is visible, there is no defense that can be shown to cover all reachable paths to the sink. The only visible path is line 12 to line 13, and it reaches the cast unconditionally.
12. (c) The SAST tool flagged this because cpp/type-confusion looks for an invalid conversion between incompatible pointer/reference types; here, line 13 performs a C-style cast from `Spiderman *` to `Ironman *`. Since no cited defense actually checks type compatibility before line 13, the finding is not disproven by the provided code.
