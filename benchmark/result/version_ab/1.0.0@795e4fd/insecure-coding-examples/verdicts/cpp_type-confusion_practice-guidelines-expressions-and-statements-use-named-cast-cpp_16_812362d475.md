# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The flagged invalid type conversion is directly present at line 16, and no visible type check or other defense guards the path from the `Spiderman` allocation at line 12 to the `Ironman *` reinterpretation at line 16. Confidence is low because the snippet does not show a subsequent dereference or attacker-controlled input, so exploitability beyond the invalid conversion itself is not fully demonstrated. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line: The flagged line is present at line 16: `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. The rule-described construct is present: a `reinterpret_cast` converts a `Spiderman *` value, `peter`, into an `Ironman *`.
2. Step 1: The potentially dangerous value originates from local heap allocation at line 12: `Spiderman * peter = new Spiderman;`. No user input, file, network, or database source is visible in the provided context.
3. Step 2: Data flow is: line 12 allocates a `Spiderman` object with `new Spiderman`; line 12 stores that pointer in `Spiderman * peter`; line 16 passes `peter` into `reinterpret_cast<Ironman *>(peter)`; line 16 stores the converted pointer in `Ironman * tony3`.
4. Step 3: No validation, sanitization, or type-safety check is visible on the path from line 12 to line 16. There is no visible `dynamic_cast` with a null check guarding `tony3`, no visible inheritance/type guarantee, and no other check proving that the object allocated as `Spiderman` at line 12 is safely usable as `Ironman` at line 16.
5. Step 4: The sink is line 16: `reinterpret_cast<Ironman *>(peter)`. The unsafe operation is the reinterpretation of a pointer to an object allocated as `Spiderman` into an `Ironman *`, which can create a type-confused pointer.
6. Step 5: No framework or library protection is visible. This is raw C++ pointer casting in `main` at lines 12-18.
7. Step 6: The code is in `main` at line 11 and the path to line 16 appears directly reachable if `main` executes. No authentication or privilege boundary is visible in the provided context.
8. Step 7: If the type-confused `Ironman *` were dereferenced or otherwise used, the potential security impact could include undefined behavior, memory corruption, crash/DoS, and in severe cases code execution. The provided snippet does not show a later dereference of `tony3`, so the concrete exploit impact is not fully demonstrated in this slice.
9. Step 8: The weakest link is the unchecked `reinterpret_cast` at line 16. There is no visible defense chain for this conversion; the prior conclusion that lack of later use was a complete defense does not actually validate the safety of the cast itself.
10. (a) Specific defense observed: None. There is no line in the provided code that validates the dynamic type of `peter` before line 16 or prevents the invalid conversion. Line 18 shows a separate `dynamic_cast<Ironman *>(peter)`, but it occurs after the flagged line and does not guard `tony3`.
11. (b) Coverage of all reachable paths: Because no defense is present before the sink, there is no visible mechanism that covers all reachable paths to line 16. The path from allocation at line 12 to the cast at line 16 is direct.
12. (c) Why SAST flagged this: The `cpp/type-confusion` rule looks for invalid conversions between incompatible pointer/object types. It flagged line 16 because `reinterpret_cast<Ironman *>(peter)` converts a `Spiderman *` to an `Ironman *`. Since no cited defense checks or proves type compatibility before line 16, the rule's concern is not neutralized by the provided code.
