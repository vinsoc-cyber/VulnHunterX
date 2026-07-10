# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** TP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

I cannot enumerate a concrete defense with line references: the flagged line 13 performs the invalid `Spiderman *` to `Ironman *` conversion directly, and nothing before it checks type compatibility. Confidence is low because the visible snippet does not show a later dereference or attacker-controlled source, but the specific CodeQL-reported invalid conversion is present and undefended. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line location: The flagged line is line 13: `Ironman * tony1 = (Ironman *)peter;`. The construct described by the rule is present on that line: a C-style pointer cast converts `peter` from `Spiderman *` to `Ironman *`.
2. (a) Specific defense observed: No specific defense is visible in the provided code for the flagged line 13. There is no type check, no `dynamic_cast` guarding `tony1`, no null check after a checked cast, and no visible class hierarchy guarantee proving `Spiderman *` can safely be treated as `Ironman *`. The separate `dynamic_cast<Ironman *>(peter)` on line 18 does not defend the earlier C-style cast on line 13.
3. (b) Coverage of all reachable paths to the sink: Because no defense is visible before line 13, there is no mechanism shown that covers any path to the sink. The only visible path is line 12 `new Spiderman` assigned to `peter`, followed directly by the cast on line 13. Nothing between lines 12 and 13 validates that the object is actually an `Ironman` or safely convertible to `Ironman *`.
4. (c) Why the SAST tool flagged this finding: The `cpp/type-confusion` rule looks for an invalid conversion between incompatible C++ types that can cause type confusion. Here, CodeQL reports conversion from `Spiderman` to `Ironman`, and line 13 performs exactly that conversion using `(Ironman *)peter`. Since the code uses a C-style cast rather than a checked cast, and no visible defense checks type compatibility before the cast, the rule’s concern is not mitigated by the provided code.
5. Step 1: The immediate source is the heap allocation on line 12: `Spiderman * peter = new Spiderman;`. No user input, file, network, or database source is visible in the provided context.
6. Step 2: Data flow is: `new Spiderman` allocation on line 12 → assignment to `Spiderman * peter` on line 12 → C-style cast to `Ironman *` on line 13 → assignment to `Ironman * tony1` on line 13.
7. Step 3: No validation, sanitization, encoding, or type-safety check is applied before the line 13 cast. The `dynamic_cast` on line 18 is a separate later expression and does not sanitize or validate `tony1`.
8. Step 4: The sink is the invalid pointer conversion on line 13: `(Ironman *)peter`. The dangerous operation is treating a `Spiderman *` as an `Ironman *`, which is the type-confusion pattern reported by the rule.
9. Step 5: No framework or library protection is visible. C++ does not automatically make a C-style cast between unrelated pointer types safe.
10. Step 6: The code path is `main` beginning at line 11. No authentication or privilege requirement is visible in the provided code.
11. Step 7: The potential impact of type confusion is memory corruption, denial of service, or possibly code execution if the wrongly typed pointer is later used. In the visible snippet, no dereference of `tony1` is shown, so concrete exploitability beyond the invalid conversion itself is not fully demonstrated.
12. Step 8: The weakest link is the unchecked C-style cast on line 13. There is no visible defense chain; the cast occurs directly after allocation and assignment on line 12.
