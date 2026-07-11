# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged signed-overflow construct is real at line 14, and the addition of `INT_MAX` and `256` is not protected by a prior safe bounds check. However, as a security vulnerability finding, the provided code shows only fixed local compile-time constants at lines 8-10 and no attacker-controlled source or reachable external input path, so exploitability is not demonstrated for this instance.

## Data flow

constant source `std::numeric_limits<int>::max()` assigned to `first_len` (line 8) and constant `256` assigned to `second_len` (line 9) → signed addition `first_len + second_len` in `if constexpr` condition (line 14) → potential guarded `memcpy` calls using `first_len`/`second_len` (lines 15-16)

## Answers

1. Q1: The flagged line is present at line 14: `if constexpr ((first_len + second_len) <= buf_len) {`. The construct described by the rule is present: a signed integer addition `first_len + second_len` is used in an overflow check/comparison. The potentially dangerous values do not originate from user input, file, network, or database; they are compile-time constants assigned in `main`: `first_len` at line 8, `second_len` at line 9, and `buf_len` at line 10.
2. Q2: Data flow is: `first_len` is assigned `std::numeric_limits<int>::max()` at line 8; `second_len` is assigned `256` at line 9; `buf_len` is assigned `256` at line 10; `first_len + second_len` is evaluated in the `if constexpr` condition at line 14; if the branch were taken, `first_len` and `second_len` would be used as copy sizes/offsets in `memcpy` calls at lines 15 and 16.
3. Q3: No validation, sanitization, or bounds-safe arithmetic is visible. There is a comparison against `buf_len` at line 14, but the addition `first_len + second_len` is performed before the comparison, so it does not prevent signed overflow for the specific issue reported.
4. Q4: The sink for this finding is the signed addition in the condition at line 14: `first_len + second_len`. Since `first_len` is `INT_MAX` from line 8 and `second_len` is `256` from line 9, adding them as `int` exceeds the representable range of signed `int`, which is the unsafe operation.
5. Q5: No framework or library automatic protection is visible. `std::numeric_limits<int>::max()` at line 8 only supplies the maximum `int` value; it does not make the arithmetic at line 14 overflow-safe. No checked-add helper, wider cast, or compiler/runtime sanitizer configuration is shown.
6. Q6: No attacker privilege or authentication state is visible or relevant in the provided code. This is `main` with fixed constants, and no external input path is shown.
7. Q7: If an attacker controlled the lengths, the security impact could be memory corruption or DoS due to an invalid overflow check followed by oversized `memcpy` operations at lines 15-16. In the provided code, however, the values are fixed constants and no attacker control is visible; concrete attacker-driven impact is not demonstrated.
8. Q8: The weakest link for correctness is the unchecked signed addition at line 14, which is performed before any effective bounds check. For security exploitability, the visible defense/limitation is that all operands are compile-time constants defined locally at lines 8-10, with no external or attacker-controlled source in the provided context.
