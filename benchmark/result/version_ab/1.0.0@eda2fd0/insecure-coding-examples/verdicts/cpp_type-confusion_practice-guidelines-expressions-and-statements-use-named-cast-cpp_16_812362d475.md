# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The invalid type conversion pattern is present at line 16, but the resulting `Ironman * tony3` is not used in the provided `main` function. A pointer reinterpretation alone, without dereference, member access, deletion through the wrong type, or passing to another sink, does not show an exploitable type-confusion vulnerability in the visible code.

## Data flow

local allocation `new Spiderman` (line 12) → assigned to `Spiderman * peter` (line 12) → cast with `reinterpret_cast<Ironman *>(peter)` (line 16) → assigned to `Ironman * tony3` (line 16), with no visible dereference or further use

## Answers

1. Step 1: The potentially dangerous value originates from local heap allocation, not from user/file/network/database input: `Spiderman * peter = new Spiderman;` on line 12. No attacker-controlled source is visible in the provided context.
2. Step 2: Data flow is: a `Spiderman` object is allocated with `new Spiderman` and assigned to `peter` on line 12; `peter` is cast to `Ironman *` using a C-style cast into `tony1` on line 13; `peter` is also cast to `Ironman *` using `reinterpret_cast` into `tony3` on line 16, which is the flagged line; `peter` is later used in `dynamic_cast<Ironman *>(peter)` into `tony4` on line 18.
3. Step 3: No validation, sanitization, or type-checking is applied before the C-style cast on line 13 or the `reinterpret_cast` on line 16. The commented-out `static_cast` on line 15 is not executed. The `dynamic_cast` on line 18 would perform a runtime type check, but it occurs after the flagged `reinterpret_cast` and does not sanitize `tony3`.
4. Step 4: The reported sink is the invalid conversion at line 16: `reinterpret_cast<Ironman *>(peter)`. The dangerous operation is treating a pointer to a `Spiderman` object as an `Ironman *`. However, in the visible code, `tony3` is only assigned and is never dereferenced, used for member access, deleted, or passed to another function.
5. Step 5: No framework or library protections are visible or relevant. This is raw C++ pointer casting in `main` on lines 12-18.
6. Step 6: No attacker privilege or authentication state is visible. The code is in `main` and uses only locally allocated objects; no external trigger or attacker-controlled input is shown.
7. Step 7: If an attacker could cause an invalid object pointer to be used as the wrong type and then dereferenced, possible impact could include undefined behavior, memory corruption, denial of service, or potentially code execution. But in the provided code, the miscast pointer `tony3` from line 16 is not used, so no concrete security impact is demonstrated.
8. Step 8: The weakest link is the unchecked invalid cast on line 16. However, the visible code path does not proceed to an unsafe use of the incorrectly typed pointer, so exploitation is not demonstrated in the provided context.
