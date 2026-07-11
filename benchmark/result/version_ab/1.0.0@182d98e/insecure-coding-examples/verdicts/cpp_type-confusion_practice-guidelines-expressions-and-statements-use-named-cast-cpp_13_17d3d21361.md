# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line does contain an invalid-looking C-style cast from `Spiderman *` to `Ironman *`, but the source is not attacker-controlled and the resulting `tony1` pointer is never dereferenced, passed onward, or otherwise used in the provided `main` function. Therefore the visible flagged path shows a bad cast/code-quality issue, but not an exploitable CWE-843 type-confusion vulnerability.

## Data flow

source `new Spiderman` allocation (line 12) → assignment to `Spiderman * peter` (line 12) → C-style cast to `Ironman *` and assignment to `tony1` (line 13)

## Answers

1. Step 0 / flagged line: line 13 is present and reads exactly: `Ironman * tony1 = (Ironman *)peter;`. The construct described by the rule is present: a C-style pointer cast from `Spiderman *` to `Ironman *`.
2. Step 1: The data originates at line 12 from `new Spiderman`, which allocates a `Spiderman` object and stores its address in `peter`. No user input, file, network, database, or other attacker-controlled source is visible in the provided code.
3. Step 2: Data flow is: `new Spiderman` allocation on line 12 → assigned to `Spiderman * peter` on line 12 → `peter` is cast to `Ironman *` and assigned to `tony1` on line 13. There is no further visible use of `tony1` after line 13.
4. Step 3: No validation, sanitization, or encoding is applied between the allocation on line 12 and the cast on line 13. For type confusion, the relevant safe check would be a valid runtime type check such as `dynamic_cast` with null checking, but that is not used for `tony1` on line 13.
5. Step 4: The sink is the C-style cast on line 13: `(Ironman *)peter`. The potentially dangerous operation is treating a pointer to a `Spiderman` object as an `Ironman *`. However, in the provided code, `tony1` is not dereferenced, used for member access, passed to another function, or deleted as an `Ironman *`.
6. Step 5: No framework or library protection is visible or relevant here. This is raw C++ pointer casting in `main` at lines 12-13.
7. Step 6: No attacker-triggerable path is visible. The code is in `main` at line 11 and allocates its own object on line 12; there is no visible input or authentication boundary.
8. Step 7: If an attacker could control such a cast and the resulting pointer were dereferenced or otherwise used as the wrong type, the impact could include memory corruption, denial of service, or possibly code execution. In this snippet, no such use occurs after the flagged line, so no concrete security impact is visible.
9. Step 8: The weakest link is the unsafe C-style cast on line 13. However, the defense chain does not need to prevent exploitation here because the cast result `tony1` is not used in the provided function; the visible code contains no dereference or other operation that would turn the bad cast into exploitable type confusion.
