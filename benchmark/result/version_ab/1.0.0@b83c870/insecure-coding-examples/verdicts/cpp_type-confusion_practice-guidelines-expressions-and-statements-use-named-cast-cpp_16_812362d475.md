# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** NMD · **Confidence:** Medium (0.65) · **Truth:** not-real · **Grade:** abstain · **Iterations:** 2

## Reasoning

The unsafe cast at line 16 is clearly present and there is no visible defense on the path from line 12 to line 16. However, the provided context omits the definitions of `Spiderman` and `Ironman`, which are needed to independently verify the type relationship and whether any C++ language-level guarantee makes the conversion safe or unsafe. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line: The flagged line is present. Line 16 is exactly `Ironman * tony3 = reinterpret_cast<Ironman *>(peter);`. The construct described by the rule is present on that line: a cast/conversion from `Spiderman *` to `Ironman *` using `reinterpret_cast`.
2. Step 1: The potentially dangerous value originates at line 12: `Spiderman * peter = new Spiderman;`. The visible source is a heap allocation, not user input, file, network, database, or another attacker-controlled source. No external input source is visible in the provided context.
3. Step 2: Data flow: line 12 allocates a `Spiderman` object with `new Spiderman`; line 12 stores that pointer in `peter`; line 16 reads `peter`; line 16 converts it to `Ironman *` with `reinterpret_cast<Ironman *>(peter)` and assigns it to `tony3`.
4. Step 3: No validation, sanitization, runtime type check, or type-safety check is visible before the flagged cast. Line 15 comments that `static_cast<Ironman *>(peter)` would fail at compile time, and line 18 uses `dynamic_cast<Ironman *>(peter)`, but neither protects the flagged `reinterpret_cast` on line 16.
5. Step 4: The sink is line 16: `reinterpret_cast<Ironman *>(peter)`. The unsafe operation is converting a `Spiderman *` into an `Ironman *`, potentially creating a pointer whose static type does not match the dynamic object type. That is the operation CodeQL flags as type confusion.
6. Step 5: No framework or library protection is visible or relevant. This is raw C++ pointer casting in `main` on lines 11-19.
7. Step 6: The code is in `main`, so it is reachable when the program executes. No authentication, authorization, or privilege boundary is visible. No attacker-controlled input path is visible either.
8. Step 7: If the converted pointer were later used as an `Ironman *`, possible impact could include undefined behavior, memory corruption, denial of service, or potentially code execution. In the shown snippet, no dereference or member access through `tony3` is visible after line 16.
9. Step 8: The weakest link is the unchecked `reinterpret_cast` on line 16. There is no visible defense that checks whether the object allocated as `Spiderman` on line 12 is safely usable as an `Ironman`.
10. (a) Specific defense observed: No concrete defense is visible in the provided code. There is no guard before line 16, no successful `dynamic_cast` result check, no type discriminator check, and no visible class hierarchy definition proving the cast is safe.
11. (b) Coverage of all reachable paths: Because no defense is visible, there is no defense to show as covering all paths. The only visible path from source to sink is line 12 → line 16, and it reaches the cast without a check.
12. (c) Why SAST flagged this: The `cpp/type-confusion` rule looks for invalid or unsafe conversions between incompatible C++ types. It flagged line 16 because `peter`, a `Spiderman *`, is converted to `Ironman *` using `reinterpret_cast`. Since no cited defense exists in the snippet, there is no visible check that addresses the rule’s concern.

## Context needed

- struct:Spiderman
- struct:Ironman
