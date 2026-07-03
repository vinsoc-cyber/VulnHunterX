# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** TP · **Confidence:** High (0.88) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The operands are fixed constants rather than attacker-controlled input, but the reported signed-overflow-check issue is concretely present: line 8 evaluates `INT_MAX + 256` in type `int`, which exceeds the maximum representable `int` value before any check can protect it. No visible cast to a wider type, overflow-safe helper, or equivalent guard prevents the signed overflow on the flagged path. [second-opinion pass: TP challenge on correctness rule]

## Answers

1. (a) Operand types: `first_len` is `const int` on line 2, `second_len` is `const int` on line 3, and `buf_len` is `const int` on line 4. In `(first_len + second_len) <= buf_len` on line 8, both addition operands are `int`, so the intermediate result of `first_len + second_len` is also `int`. The maximum value of that intermediate type is `std::numeric_limits<int>::max()`, which is exactly the value assigned to `first_len` on line 2.
2. (b) The operand values come from compile-time constants, not attacker-controlled input. `first_len` is fixed to `std::numeric_limits<int>::max()` on line 2; `second_len` is fixed to `256` on line 3; `buf_len` is fixed to `256` on line 4. No file, network, database, `argv`, or other external source is visible in the provided context.
3. (c) For this rule the operation is addition, not multiplication. With the visible bounds, the intermediate can exceed the `int` maximum: `first_len + second_len` = `INT_MAX + 256`, which is greater than `INT_MAX`. On a typical 32-bit `int`, this is `2147483647 + 256 = 2147483903 > 2147483647`. Therefore the signed `int` addition on line 8 overflows before the comparison to `buf_len` is evaluated.
4. (d) There is no widened result visible in the provided code. The overflowing intermediate result is used directly in the `if constexpr` condition on line 8. The condition guards `memcpy` calls on lines 9-10, where `first_len` is used as a copy length on line 9 and as an offset on line 10, and `second_len` is used as a copy length on line 10. However, for the specific reported rule, the dangerous operation is already the signed overflow in the check expression on line 8.
5. (e) The file path is `practice/if_constexpr.cpp`, which suggests example/practice code, and the operands are fixed compile-time fixtures rather than attacker input. However, no explicit test, benchmark, fuzz harness, or vendored-third-party marker is visible in the provided context.
