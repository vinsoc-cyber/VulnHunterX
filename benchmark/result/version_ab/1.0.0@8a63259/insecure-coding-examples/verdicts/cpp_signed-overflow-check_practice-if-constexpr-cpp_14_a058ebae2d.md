# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged signed-overflow construct is genuinely present on line 14, but the provided code shows only hard-coded compile-time constants from lines 8-10 and no attacker-controlled source or reachable external data path. Therefore this is a real correctness/undefined-behavior pattern, but not a demonstrated exploitable security vulnerability in the provided context.

## Data flow

hard-coded constant `std::numeric_limits<int>::max()` assigned to `first_len` (line 8) and hard-coded literal `256` assigned to `second_len` (line 9) → no validation or widening → signed addition `first_len + second_len` in `if constexpr` condition (line 14)

## Answers

1. Step 0 / locating flagged line: The flagged line 14 is exactly `if constexpr ((first_len + second_len) <= buf_len) {`. The rule-described construct is present on that line: it performs signed integer addition `first_len + second_len` inside a comparison intended to check whether the combined length fits in `buf_len`.
2. Step 1: The potentially dangerous values do not originate from user input, file, network, or database in the provided code. They are hard-coded local constants: `first_len` is `std::numeric_limits<int>::max()` on line 8, `second_len` is `256` on line 9, and `buf_len` is `256` on line 10.
3. Step 2: Data flow is: `std::numeric_limits<int>::max()` assigned to `const int first_len` on line 8; literal `256` assigned to `const int second_len` on line 9; literal `256` assigned to `const int buf_len` on line 10; `first_len + second_len` is evaluated in the `if constexpr` condition on line 14; if the condition were taken, the lengths are used in `memcpy` calls on lines 15 and 16.
4. Step 3: No validation, sanitization, or encoding is applied between the assignments on lines 8-10 and the signed addition on line 14. There is also no cast to a wider type such as `long long` or `size_t` before addition. However, the values are compile-time constants and not attacker-controlled in the provided context.
5. Step 4: The sink for the reported rule is the signed addition/comparison on line 14: `(first_len + second_len) <= buf_len`. The dangerous operation is adding two signed `int` values where `first_len` is `INT_MAX` and `second_len` is `256`, which exceeds the range of `int`. The later `memcpy` calls on lines 15-16 are not the sink for this specific CodeQL rule.
6. Step 5: No framework or library automatic protection is visible or relevant here. `std::numeric_limits<int>::max()` on line 8 only supplies the maximum representable `int`; it does not protect the subsequent signed addition on line 14.
7. Step 6: No attacker privilege level or authentication state is visible or applicable. The code is in `main` starting at line 7 and uses only hard-coded constants on lines 8-10. There is no visible external input path for an attacker to trigger with chosen values.
8. Step 7: If attacker-controlled data reached this pattern in a real program, the impact could be incorrect bounds checking due to signed overflow/undefined behavior, potentially leading to buffer overflow or memory corruption. In this provided snippet, because the values are hard-coded constants and not externally controlled, no concrete attacker-driven security impact is demonstrated.
9. Step 8: The weakest link for correctness is the unchecked signed addition on line 14 without widening or precondition checks. For security exploitability, the defense is complete in the provided context because the operands are fixed local constants from lines 8-10 and no attacker-controlled source is visible.
