# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged line is present and is exactly `memcpy(buf, first, first_len);` on line 15, matching the static-buffer-overflow pattern because `buf` is 256 bytes on line 11 while `first_len` is `INT_MAX` from line 8. However, the line is inside an `if constexpr` whose condition on line 14 performs signed integer overflow in a required constant expression, making the program ill-formed in conforming C++ and preventing an executable vulnerable path from being produced.

## Data flow

constant `std::numeric_limits<int>::max()` assigned to `first_len` (line 8) → `first_len` used in overflowing `if constexpr` condition (line 14) → `first_len` used as `memcpy` length into 256-byte `buf` (line 15)

## Answers

1. No attacker-controlled source is visible. The relevant values originate from compile-time constants: `first_len = std::numeric_limits<int>::max()` on line 8, `second_len = 256` on line 9, and `buf_len = 256` on line 10.
2. `first_len` is assigned on line 8, used as the size of `first` on line 11, used in the `if constexpr` condition on line 14, and used as the `memcpy` length on the flagged line 15. `buf_len` is assigned on line 10, used to size `buf` on line 11, and used in the guard condition on line 14. `buf` is declared as `char buf[buf_len]` on line 11, so its size is 256.
3. There is an apparent bounds check on line 14: `if constexpr ((first_len + second_len) <= buf_len)`. However, `first_len + second_len` overflows signed `int` because `first_len` is `INT_MAX` and `second_len` is 256. In a conforming C++ constant expression, that overflow makes the condition ill-formed rather than a valid runtime protection. No runtime validation or sanitization is visible before line 15.
4. The sink is the flagged line 15: `memcpy(buf, first, first_len);`. The dangerous operation is copying `first_len` bytes, i.e. `INT_MAX`, into `buf`, which has only 256 bytes as declared on line 11.
5. No framework-level or library-level automatic protection is visible. `memcpy` is a raw C memory-copy routine and does not perform destination bounds checking.
6. No attacker-triggering privilege level is visible in the provided context. The code is in `main` starting at line 7 and uses only constants; there is no visible user, file, network, or database input.
7. If the flagged `memcpy` were executable, the concrete impact would be a severe out-of-bounds write to `buf` on line 15, potentially causing memory corruption, crash/DoS, or arbitrary code execution in a native C++ program. However, no attacker-controlled data path is visible.
8. The weakest link would be the invalid/unsafe size calculation in the guard on line 14 combined with raw `memcpy` on line 15. However, for the specific reported runtime buffer overflow, the visible C++ language rule for `if constexpr` constant evaluation prevents this code from compiling in a conforming implementation because the signed overflow in the constant expression on line 14 is ill-formed.
