# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** FP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged signed-overflow pattern is genuinely present at line 14, and the expression is a correctness bug. However, the provided code shows only fixed local constants and no attacker-controlled source, so there is no clearly exploitable security path for this finding.

## Data flow

constant `std::numeric_limits<int>::max()` → `first_len` (line 8); constant `256` → `second_len` (line 9); constant `256` → `buf_len` (line 10); `first_len + second_len` signed addition in comparison at line 14

## Answers

1. Step 0: The flagged line is present at line 14: `if constexpr ((first_len + second_len) <= buf_len) {`. The construct described by the rule is present: signed integer addition `first_len + second_len` is used in an overflow-sensitive comparison.
2. Step 1: The potentially dangerous data does not originate from user input, file, network, database, or any external source in the provided code. The values are compile-time constants assigned locally: `first_len` at line 8, `second_len` at line 9, and `buf_len` at line 10.
3. Step 2: Data flow is: `std::numeric_limits<int>::max()` assigned to `first_len` at line 8; literal `256` assigned to `second_len` at line 9; literal `256` assigned to `buf_len` at line 10; `first_len + second_len` is evaluated in the `if constexpr` condition at line 14; if the branch were taken, `first_len` and `second_len` would be used in `memcpy` calls at lines 15-16.
4. Step 3: No validation, sanitization, or bounds checking is applied before line 14. However, the operands are visible local constants, not attacker-controlled data. There is no runtime input requiring sanitization in the shown code.
5. Step 4: The sink for this finding is the signed addition/comparison at line 14: `(first_len + second_len) <= buf_len`. The dangerous operation is signed integer addition where `first_len` is `INT_MAX` and `second_len` is `256`, which would overflow the range of `int`.
6. Step 5: No framework or library protection is involved. `std::numeric_limits<int>::max()` at line 8 only provides the maximum `int` value; it does not prevent overflow in the later addition at line 14.
7. Step 6: No attacker privilege level or authentication state is visible or relevant in the provided context. This is `main` at line 7 and uses only local constants, so there is no visible attacker-controlled trigger.
8. Step 7: If an attacker controlled these values, the impact could include incorrect bounds checks and potentially unsafe `memcpy` behavior at lines 15-16. In the provided code, however, the values are fixed constants, so no concrete attacker-driven security impact is visible.
9. Step 8: The weakest link is the unchecked signed addition at line 14. There is no defensive overflow-safe arithmetic. However, for security exploitability, the defense chain is effectively complete because the relevant operands are fixed local constants and no attacker-controlled source is visible.
