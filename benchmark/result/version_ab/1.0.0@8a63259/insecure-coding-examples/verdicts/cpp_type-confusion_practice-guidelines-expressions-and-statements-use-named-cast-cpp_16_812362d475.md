# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The flagged type-confusion construct is present at line 16, and there is no visible defense such as a prior successful `dynamic_cast` or type guard. Confidence is low because the provided code does not show `tony3` being dereferenced or otherwise used after the invalid cast, so exploitability beyond the invalid conversion itself is not demonstrated. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: No concrete defense is visible. Line 16 contains the exact flagged operation: `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. There is no visible type check, successful `dynamic_cast`, validation, or guard before this cast. My previous rationale relied on the fact that `tony3` is not visibly used after line 16, but that is not a defense mechanism against the invalid conversion itself.
2. (b) Coverage of all reachable paths: No defense covers all reachable paths to the sink. The path is direct: line 12 allocates `new Spiderman` into `peter`, and line 16 casts `peter` to `Ironman *` using `reinterpret_cast`. There is no branch, guard, or sanitizer between line 12 and line 16. The commented-out `static_cast` on line 15 is not executable code, and the `dynamic_cast` on line 18 occurs after the flagged sink, so it cannot protect line 16.
3. (c) Why the SAST tool flagged this: The `cpp/type-confusion` rule looks for invalid or unsafe conversions where an object of one type may be treated as an incompatible type, causing CWE-843 type confusion. The construct is present at line 16: a `Spiderman *` value named `peter` is converted to `Ironman *` using `reinterpret_cast`. The absent-use observation is not a type-safety check and does not validate that `peter` actually points to an `Ironman` object.
4. Step 1: The potentially dangerous value originates at line 12 from local heap allocation: `Spiderman * peter = new Spiderman;`. No user input, file, network, or database source is visible in the provided context.
5. Step 2: Data flow is: `new Spiderman` at line 12 → assigned to `Spiderman * peter` at line 12 → used as the operand to `reinterpret_cast<Ironman *>(peter)` at line 16 → assigned to `Ironman * tony3` at line 16.
6. Step 3: No validation, sanitization, encoding, or runtime type verification is applied before line 16. The `dynamic_cast<Ironman *>(peter)` at line 18 is after the sink and does not protect `tony3`.
7. Step 4: The sink is line 16. The unsafe operation is `reinterpret_cast<Ironman *>(peter)`, which treats a pointer to a `Spiderman` object as a pointer to `Ironman` without runtime type checking.
8. Step 5: No framework or library protection is visible. This is raw C++ pointer casting. C++ does not automatically validate a `reinterpret_cast` between unrelated object pointer types.
9. Step 6: Required privilege or authentication state is not visible in the provided context. The code is in `main` at lines 11-19 and has no visible external input or access-control context.
10. Step 7: Concrete security impact is limited by the provided slice because `tony3` is not visibly dereferenced after line 16. However, the invalid conversion itself creates a wrongly typed pointer; if used, it could lead to undefined behavior, memory corruption, or DoS.
11. Step 8: The weakest link is the unchecked `reinterpret_cast` at line 16. There is no visible defense that proves `peter` actually points to an `Ironman` object before the conversion.
