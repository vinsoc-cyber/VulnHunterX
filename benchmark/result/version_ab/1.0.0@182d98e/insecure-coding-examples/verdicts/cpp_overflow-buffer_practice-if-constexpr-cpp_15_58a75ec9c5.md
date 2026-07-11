# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged sink is a real unsafe `memcpy`: line 15 copies `INT_MAX` bytes from `first` into `buf`, while `buf` is only 256 bytes by lines 10-11, and `memcpy` provides no bounds checking. Although no attacker-controlled source is visible and the `if constexpr` condition on line 14 involves signed overflow/ill-formed constant evaluation concerns, the provided code shows no adequate visible defense for the flagged memory-copy operation if instantiated/executed.

## Data flow

std::numeric_limits<int>::max() (line 8) → const int first_len (line 8) → memcpy byte count argument (line 15); buf_len = 256 (line 10) → char buf[buf_len] destination buffer (line 11) → memcpy destination (line 15)

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 15: `memcpy(buf, first, first_len);`. The construct described by the rule is present: this is a `memcpy` call copying `first_len` bytes into `buf`.
2. Step 1: No potentially dangerous external data source is visible. The copy length originates from the compile-time constant `first_len`, initialized to `std::numeric_limits<int>::max()` on line 8. There is no user input, file, network, database, or other attacker-controlled source shown.
3. Step 2: Data flow is: `std::numeric_limits<int>::max()` on line 8 → assigned to `const int first_len` on line 8 → used as the size of `first` on line 11 → used as the `memcpy` byte count on line 15. Separately, `buf_len` is set to 256 on line 10 → used to declare `char buf[buf_len]` on line 11 → `buf` is the destination on line 15.
4. Step 3: There is an attempted bounds condition on line 14: `if constexpr ((first_len + second_len) <= buf_len)`. However, `first_len + second_len` overflows signed `int` in standard C++ because `first_len` is `INT_MAX` and `second_len` is 256. This is not a valid reliable runtime validation or sanitization for the `memcpy` size. No other validation, sanitization, or encoding is visible.
5. Step 4: The sink is line 15: `memcpy(buf, first, first_len);`. It is dangerous because `buf` is declared as 256 bytes on line 11 via `buf_len` from line 10, while `first_len` is `INT_MAX` from line 8, so the requested copy size vastly exceeds the destination buffer size.
6. Step 5: No framework or library-level automatic protection is visible. `memcpy` is a raw C library memory-copy primitive and performs no destination bounds checking.
7. Step 6: No attacker privilege or authentication state is visible. The code is in `main` at line 7 and has no inputs in the provided context. An attacker-controlled trigger is not shown.
8. Step 7: If this copy were executed, the concrete impact would be memory corruption, likely stack buffer overflow and process crash/DoS, with potential code execution depending on environment. However, attacker control over the data or path is not visible in the provided code.
9. Step 8: The weakest link is the invalid/inadequate bounds check on line 14: it attempts to compare combined lengths against `buf_len`, but the addition itself overflows signed `int`. There is no complete visible defense that safely proves `first_len <= sizeof(buf)` before line 15.
