# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The invalid cast pattern reported by the rule is present on line 13, but the provided code does not use, dereference, pass, or delete the resulting `Ironman *tony1`. Since the miscast pointer is not used on the shown path, the provided context does not demonstrate exploitable CWE-843 type confusion.

## Data flow

source `new Spiderman` (line 12) → assignment to `Spiderman *peter` (line 12) → C-style cast `(Ironman *)peter` (line 13) → assignment to `Ironman *tony1` (line 13)

## Answers

1. Step 1: The vulnerability class is CWE-843 type confusion / invalid object type conversion. The potentially dangerous value originates from a local heap allocation, `new Spiderman`, on line 12. No user input, file, network, or database source is visible in the provided context.
2. Step 2: Data flow: `new Spiderman` creates a `Spiderman` object on line 12 → its pointer is assigned to `Spiderman *peter` on line 12 → `peter` is converted with a C-style cast to `Ironman *` and assigned to `tony1` on line 13. The same `peter` value is also later converted with `reinterpret_cast<Ironman *>` on line 16 and `dynamic_cast<Ironman *>` on line 18, but the flagged line is line 13.
3. Step 3: No validation, sanitization, or encoding is applied between allocation on line 12 and the C-style cast on line 13. For type confusion, the relevant defense would be a proven inheritance relationship, checked cast, or runtime type validation; none is visible before line 13.
4. Step 4: The sink for the reported finding is the invalid pointer conversion on line 13: `Ironman * tony1 = (Ironman *)peter;`. The dangerous operation is treating a `Spiderman *` as an `Ironman *`. However, in the provided function, `tony1` is not dereferenced, used for member access, passed elsewhere, or freed as `Ironman *` after the cast.
5. Step 5: No framework or library protection is visible. This is raw C++ pointer casting in `main` on lines 12-18, with no automatic type-safety protection for the C-style cast on line 13.
6. Step 6: The code is inside `main` on line 11. No authentication, privilege boundary, or attacker-triggerable input path is visible in the provided context. The code path appears to execute when the program runs, but attacker control is not visible.
7. Step 7: If attacker-controlled data could influence this pattern and the resulting `Ironman *` were later dereferenced or used polymorphically, the potential impact could include undefined behavior, memory corruption, denial of service, or possibly code execution. In the provided context, there is no dereference or use of `tony1`, so no concrete security impact is demonstrated.
8. Step 8: The weakest link is the unchecked C-style cast on line 13, which bypasses C++ type safety. However, the provided code also shows a complete local flow where the cast result is not used afterward, so the defense against exploitation on this shown path is that no unsafe access occurs through the miscast pointer.
