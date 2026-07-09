# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** Medium (0.7) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

Step 0: the flagged line is present and is exactly `memcpy(buf, first, first_len);` on line 15, so the reported memcpy construct is present. Although the call would overflow a 256-byte buffer if executed, the provided code uses only constants, has no attacker-controlled source, and the enclosing `if constexpr` condition on line 14 performs signed constant-expression overflow in standard C++, so there is no clearly exploitable conforming runtime path shown for the reported security issue.

## Data flow

constant `std::numeric_limits<int>::max()` assigned to `first_len` (line 8) → used in overflow-prone compile-time condition `(first_len + second_len) <= buf_len` (line 14) → used as memcpy length in `memcpy(buf, first, first_len)` (line 15), where `buf` has visible length 256 from lines 10-11

## Answers

1. Q1: The potentially dangerous size value originates from compile-time constants, not from user input: `first_len` is initialized to `std::numeric_limits<int>::max()` on line 8, `second_len` to 256 on line 9, and `buf_len` to 256 on line 10. No file, network, database, or request-derived source is visible.
2. Q2: Data flow: `first_len` is assigned `INT_MAX` on line 8; `buf_len` is assigned 256 on line 10; `buf` is declared as `char buf[buf_len]` on line 11, so its visible intended size is 256 bytes; line 14 evaluates `(first_len + second_len) <= buf_len`; line 15 passes `first_len` as the third argument to `memcpy(buf, first, first_len)`.
3. Q3: The only visible check is the `if constexpr` condition on line 14: `(first_len + second_len) <= buf_len`. It is not a sufficient runtime bounds validation for the flagged operation. In standard C++, `first_len + second_len` overflows signed `int` during constant-expression evaluation, making the program ill-formed rather than providing a valid safety check.
4. Q4: The sink is the flagged line 15: `memcpy(buf, first, first_len);`. The dangerous operation is copying `first_len` bytes, where `first_len` is `INT_MAX` from line 8, into `buf`, which is declared with length `buf_len` equal to 256 on lines 10-11. If this line were reachable in a compiled execution, it would overflow `buf`.
5. Q5: No framework or library-level automatic protection is visible. `memcpy` performs no bounds checking; it copies exactly the byte count supplied by the caller on line 15.
6. Q6: No attacker privilege or authentication state is visible. The code is in `main` on line 7 and uses only constants. There is no visible attacker-controlled input required or accepted.
7. Q7: If an attacker could somehow cause execution of the flagged copy with these values, the impact would be memory corruption/stack buffer overflow and likely denial of service, with possible code execution in a broader vulnerable program. However, in the provided code, the size is not attacker-controlled and the standard C++ constant-expression overflow at line 14 prevents a valid conforming runtime path.
8. Q8: The weakest link in the defensive chain is the attempted size check on line 14, because it computes `first_len + second_len` in signed `int` and overflows. However, for the reported security finding, the visible code also shows no attacker-controlled source and no conforming C++ runtime path through the `if constexpr` condition.
