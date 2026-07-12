# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** FP · **Confidence:** Medium (0.72) · **Truth:** real · **Grade:** MISS · **Iterations:** 2

## Reasoning

The signed-overflow pattern is genuinely present on line 14 and the fixed arithmetic `INT_MAX + 256` exceeds `int` range, but the operands are compile-time constants in a practice/example file, not attacker-controlled data. Because no external input can reach the arithmetic or subsequent memcpy sizes in the provided context, this is a correctness/demo issue rather than an exploitable security vulnerability. [second-opinion pass: TP challenge on correctness rule]

## Answers

1. Step 0 / flagged line: The flagged line is present at line 14: `if constexpr ((first_len + second_len) <= buf_len) {`. The construct is signed arithmetic in a check: `first_len + second_len` is evaluated before comparison to `buf_len`.
2. (a) Operand and intermediate types: `first_len`, `second_len`, and `buf_len` are all declared `const int` on lines 8-10. Therefore both operands of `first_len + second_len` on line 14 are `int`, and the intermediate result type is also `int`. The maximum value of `int` is explicitly used on line 8 as `std::numeric_limits<int>::max()`, i.e. `INT_MAX`.
3. (b) Operand values: The operands come from compile-time constants, not attacker-controlled input. `first_len` is assigned `std::numeric_limits<int>::max()` on line 8; `second_len` is assigned literal `256` on line 9; `buf_len` is assigned literal `256` on line 10. There is no file, network, argv, database, or other external input visible in the provided code.
4. (c) Arithmetic bounds: This line performs addition, not multiplication. With the visible bounds, the expression is `INT_MAX + 256`, which exceeds the maximum value representable by the intermediate type `int`, whose max is `INT_MAX`. Therefore the signed addition itself would overflow if evaluated as signed `int` arithmetic.
5. (d) Dangerous use of result: The result of the addition is used only in the `if constexpr` condition on line 14. The branch contains potentially dangerous `memcpy` calls on lines 15-16 using `first_len` and `second_len` as copy sizes, but those values are fixed compile-time constants, not attacker-controlled lengths. There is no widened allocation/index/length derived from attacker-controlled data visible here.
6. (e) Test/fixture context: The file path is `practice/if_constexpr.cpp`, and the nearby comment on line 13 says `// Undefined behavior (negative)`, indicating this is likely a small practice/test-style example demonstrating the pattern. From the visible code, the operands are fixed fixtures rather than attacker-controlled input.
