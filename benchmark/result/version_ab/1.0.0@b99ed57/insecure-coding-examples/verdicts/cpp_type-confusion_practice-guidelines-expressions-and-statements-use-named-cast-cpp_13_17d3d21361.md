# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** NMD · **Confidence:** Medium (0.6) · **Truth:** not-real · **Grade:** abstain · **Iterations:** 2

## Reasoning

The previous False Positive verdict cannot be justified under the requested standard because no concrete defense is visible on the path from line 12 to the flagged sink at line 13. The flagged invalid-cast pattern is present, but the provided context lacks the class definitions and any broader context needed to assess whether the invalid pointer can cause exploitable type confusion beyond the cast itself. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: No concrete defense is visible in the provided code. Line 13 performs `Ironman * tony1 = (Ironman *)peter;`, a C-style cast from `Spiderman *` to `Ironman *`. There is no visible runtime type check, safe `dynamic_cast` guard, bounds/lifetime validation, or subsequent check on `tony1` before or at the sink.
2. (b) Coverage of all reachable paths to the sink: No defense can be shown to cover all paths. The only visible path is line 12 `Spiderman * peter = new Spiderman;` flowing directly to line 13 `(Ironman *)peter`. There is no branch or guard between line 12 and line 13. Although `tony1` is not visibly dereferenced later in the provided snippet, that is absence of a later dangerous use, not a defense at the flagged cast itself.
3. (c) Why the SAST tool flagged this: The `cpp/type-confusion` rule looks for invalid conversions where an object of one type may be treated as an incompatible type, here reported as conversion from `Spiderman` to `Ironman`. The flagged line 13 contains exactly that pattern: `Ironman * tony1 = (Ironman *)peter;`. No cited defense is actually checking the type relationship at line 13. The commented `static_cast` on line 15 and `dynamic_cast` on line 18 do not protect the line-13 cast.
4. Step 1: The visible source is local heap allocation at line 12: `new Spiderman`. No user input, file, network, database, or attacker-controlled source is visible in the provided context.
5. Step 2: Data flow is line 12 `new Spiderman` → line 12 assignment to `Spiderman * peter` → line 13 C-style cast `(Ironman *)peter` → line 13 assignment to `Ironman * tony1`.
6. Step 3: No validation, sanitization, encoding, or type-safe runtime check is applied on the line-12 to line-13 path. The `dynamic_cast` at line 18 is a separate assignment to `tony4` and does not sanitize or guard `tony1`.
7. Step 4: The sink is line 13, where `peter` is cast to `Ironman *` using a C-style cast. The dangerous operation is bypassing C++ type safety and potentially creating a pointer of an incompatible static type.
8. Step 5: No framework or library automatic protection is visible. This is raw C++ pointer conversion.
9. Step 6: The privilege/authentication required to trigger this code path is not visible. The code is in `main` at line 11, but no caller or external trigger information is provided.
10. Step 7: If the resulting invalid pointer were used, concrete impacts could include undefined behavior, memory corruption, crash/DoS, or potentially code execution depending on class layout and later use. In the visible snippet, no dereference or use of `tony1` after line 13 is shown.
11. Step 8: The weakest link is the unchecked C-style cast on line 13. There is no complete defense visible; however, additional type definitions and complete surrounding context are needed to determine whether this remains only a demonstrative bad cast or creates an exploitable memory-safety vulnerability.

## Context needed

- struct:Spiderman
- struct:Ironman
- function:main
