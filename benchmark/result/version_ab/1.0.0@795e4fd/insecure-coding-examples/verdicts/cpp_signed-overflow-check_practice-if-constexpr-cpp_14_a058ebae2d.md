# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** FP · **Confidence:** Medium (0.7) · **Truth:** real · **Grade:** MISS · **Iterations:** 2

## Reasoning

The signed-overflow pattern is genuinely present, and the constant expression `INT_MAX + 256` exceeds the maximum `int` value on line 14. However, the operands are fixed compile-time constants with no attacker-controlled source visible, and no attacker-controlled overflowing value is shown flowing into a dangerous runtime sink; therefore this is a correctness/type-hygiene issue rather than a demonstrated exploitable vulnerability. [second-opinion pass: TP challenge on correctness rule]

## Answers

1. Step 0 / flagged line: The flagged line is present at line 14: `if constexpr ((first_len + second_len) <= buf_len) {`. The rule-relevant construct is present on that line: a signed `int` addition, `first_len + second_len`, is used as part of an overflow/bounds-style check before comparison with `buf_len`.
2. (a) Operand and intermediate types: `first_len`, `second_len`, and `buf_len` are all declared as `const int` on lines 8-10. Therefore `first_len + second_len` on line 14 is evaluated as `int + int`, producing an intermediate result of type `int`. The maximum value is `std::numeric_limits<int>::max()`, which is exactly the value assigned to `first_len` on line 8. This code involves addition, not multiplication/product.
3. (b) Operand values: The values come from fixed compile-time constants, not attacker-controlled input. `first_len` is assigned `std::numeric_limits<int>::max()` on line 8; `second_len` is assigned the literal `256` on line 9; `buf_len` is assigned the literal `256` on line 10. There is no visible source from file, network, argv, database, or user input.
4. (c) Arithmetic bound: For the actual addition on line 14, the maximum/actual operands are `first_len = INT_MAX` and `second_len = 256`. The intermediate computation is `INT_MAX + 256`, which is greater than `INT_MAX`, so it cannot be represented in type `int`. Therefore the signed `int` addition on line 14 does overflow as written. There is no product in the provided code.
5. (d) Use of result: The overflowing intermediate result is used in the `if constexpr` comparison on line 14: `(first_len + second_len) <= buf_len`. The guarded block contains `memcpy` calls on lines 15-16, which would be dangerous if an incorrect runtime bounds check allowed them. However, in this exact code, the operands are compile-time constants and the overflow occurs in a constant-expression context; no attacker-controlled widened result is shown flowing into an allocation, index, or memcpy size.
6. (e) File role: The file path is `practice/if_constexpr.cpp`, and the comment on line 13 says `// Undefined behavior (negative)`, suggesting this may be a practice/example fixture. However, whether it is a test, benchmark, fuzz harness, or vendored third-party copy is not conclusively visible from the provided context alone.
7. Q1 source: The potentially dangerous values originate from compile-time constants on lines 8-10, not from user input.
8. Q2 trace: `std::numeric_limits<int>::max()` on line 8 → `first_len`; literal `256` on line 9 → `second_len`; literal `256` on line 10 → `buf_len`; `first_len + second_len` evaluated on line 14; compared with `buf_len` on line 14.
9. Q3 validation/sanitization: No validation, sanitization, or pre-addition overflow guard is visible. There is no check like `first_len <= INT_MAX - second_len` before line 14.
10. Q4 sink: For the reported rule, the sink is the signed addition in the condition on line 14. The later `memcpy` calls on lines 15-16 are not reached by attacker-controlled sizes in the shown code.
11. Q5 framework/library protections: No framework or library protection is visible. `std::numeric_limits<int>::max()` on line 8 provides the maximum `int` value but does not make the addition on line 14 safe.
12. Q6 attacker privilege: No attacker privilege or authentication state is visible or relevant because the operands are fixed constants in `main` on lines 8-10.
13. Q7 security impact: As a security vulnerability, no concrete attacker-driven impact is demonstrated in the provided code because there is no attacker-controlled source. The code does demonstrate a signed-overflow correctness issue on line 14.
14. Q8 weakest link: The weakest link for correctness is the unchecked signed addition on line 14. For exploitability, the missing link is attacker control or any shown runtime path where untrusted values reach the arithmetic and then a dangerous sink.
