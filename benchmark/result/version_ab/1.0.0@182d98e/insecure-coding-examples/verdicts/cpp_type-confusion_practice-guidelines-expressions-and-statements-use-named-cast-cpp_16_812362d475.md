# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** NMD · **Confidence:** Medium (0.6) · **Truth:** not-real · **Grade:** abstain · **Iterations:** 2

## Reasoning

The flagged line clearly performs the suspicious cast and no concrete defense is visible before it. However, the provided slice does not include the definitions of `Spiderman` and `Ironman`, so I cannot independently verify their relationship or whether the conversion is truly invalid beyond the CodeQL message. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line: The flagged line is present at line 16 and reads exactly: `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. The construct described by the rule is present on that line: a pointer value originating as `Spiderman *` is converted to `Ironman *` using `reinterpret_cast`.
2. Step 1: The immediate source is line 12: `Spiderman * peter = new Spiderman;`. No ultimate external source such as user input, file, network, or database is visible in the provided context.
3. Step 2: The flagged data flow is: line 12 allocates a `Spiderman` object with `new`; line 12 assigns that object pointer to `peter`; line 16 passes `peter` into `reinterpret_cast<Ironman *>(peter)` and assigns the result to `tony3`. Line 13 also performs a C-style cast from `peter` to `Ironman *`, and line 18 performs `dynamic_cast<Ironman *>(peter)`, but the flagged sink is line 16.
4. Step 3: No validation or sanitization is visible before line 16. The only potentially type-safe operation shown is `dynamic_cast<Ironman *>(peter)` on line 18, but it occurs after the flagged `reinterpret_cast` and does not protect or validate the assignment to `tony3` on line 16.
5. Step 4: The sink is line 16: `reinterpret_cast<Ironman *>(peter)`. The unsafe operation is converting a pointer to a `Spiderman` object into an `Ironman *`, which can create type confusion if the resulting pointer is accessed as an `Ironman`.
6. Step 5: No framework or library automatic protection is visible. This is raw C++ pointer casting in `main` at lines 12-18.
7. Step 6: The privilege level or authentication state needed to trigger this code path is not visible in the provided context. The function is `main` at line 11, but no invocation constraints or attacker-controlled inputs are shown.
8. Step 7: If the invalidly cast pointer were later dereferenced or otherwise used as an `Ironman`, the impact could include undefined behavior, memory corruption, crash/DoS, or potentially code execution. In the provided lines, no dereference of `tony3` is visible, so concrete exploitability cannot be confirmed from this slice alone.
9. Step 8: The weakest link is line 16: the unchecked `reinterpret_cast` from `Spiderman *` to `Ironman *`. I cannot identify a concrete defense at or before line 16 that proves the cast is safe.
10. (a) Specific defense observed: None. There is no visible guard, `dynamic_cast` result check, common-base type check, or other validation before the flagged line 16. The later `dynamic_cast` on line 18 does not defend line 16.
11. (b) Coverage of all reachable paths: Because no defense is visible, there is no mechanism shown that covers all paths to line 16. Execution flows directly from allocation/assignment on line 12 to the invalid cast on line 16, with no intervening check.
12. (c) Why SAST flagged it: The `cpp/type-confusion` rule looks for invalid or suspicious conversions between incompatible C++ types. It flagged line 16 because `reinterpret_cast<Ironman *>(peter)` converts a `Spiderman *` to an `Ironman *`. Since no cited defense checks type compatibility before that cast, the finding cannot be dismissed as a defended false positive from the provided context.

## Context needed

- struct:Spiderman
- struct:Ironman
