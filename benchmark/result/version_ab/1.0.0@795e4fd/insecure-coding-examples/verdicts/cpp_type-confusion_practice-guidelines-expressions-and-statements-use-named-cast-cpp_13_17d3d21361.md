# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line does contain an invalid-looking C-style conversion from `Spiderman *` to `Ironman *`, but the only visible source is a local `new Spiderman` allocation and the resulting `tony1` pointer is never dereferenced or otherwise used in the provided function. Thus, while the cast is unsafe C++ style, the provided code does not show an exploitable CWE-843 type-confusion path.

## Data flow

heap allocation `new Spiderman` (line 12) → assignment to `Spiderman * peter` (line 12) → C-style cast `(Ironman *)peter` and assignment to `Ironman * tony1` (line 13)

## Answers

1. Step 0: The flagged line is present at line 13: `Ironman * tony1 = (Ironman *)peter;`. The construct described by the rule is present: a C-style pointer cast converts `peter`, a `Spiderman *`, to `Ironman *`.
2. Step 1: The potentially dangerous value originates from a local heap allocation at line 12: `Spiderman * peter = new Spiderman;`. No user input, file, network, or database source is visible in the provided context.
3. Step 2: Data flow is: a `Spiderman` object is allocated with `new Spiderman` on line 12, assigned to `Spiderman * peter` on line 12, then `peter` is cast to `Ironman *` and assigned to `tony1` on line 13. Separately, `peter` is also cast with `reinterpret_cast<Ironman *>` on line 16 and `dynamic_cast<Ironman *>` on line 18, but the flagged sink is line 13.
4. Step 3: No validation or sanitization is applied before the C-style cast on line 13. The commented-out `static_cast` on line 15 would fail at compile time according to the comment, and the `dynamic_cast` on line 18 is a runtime-checked cast, but neither protects the flagged C-style cast on line 13.
5. Step 4: The sink is the C-style cast on line 13: `(Ironman *)peter`. The dangerous operation is treating a `Spiderman *` as an `Ironman *`, which can create type confusion if the resulting pointer is dereferenced or otherwise used as an `Ironman` object.
6. Step 5: No framework or library automatic protections are visible. This is raw C++ pointer casting, and the C-style cast on line 13 bypasses compile-time type safety checks that would reject the conversion as indicated by the commented `static_cast` on line 15.
7. Step 6: No attacker-triggerable input path, privilege level, or authentication state is visible. The code is in `main` and allocates the object locally on line 12. Whether an attacker can trigger this code path is not visible in provided context.
8. Step 7: If an attacker could influence the object or if the incorrectly typed pointer were later used, possible impact could include undefined behavior, memory corruption, crash/DoS, or potentially code execution. However, in the provided code, `tony1` is not dereferenced or otherwise used after the cast, so no concrete security impact is visible.
9. Step 8: The weakest link is the unsafe C-style cast on line 13, which bypasses type safety. However, the provided code also shows no attacker-controlled source and no subsequent use of `tony1`, so the chain to an exploitable security issue is incomplete in this snippet.
