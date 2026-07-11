# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** Medium (0.7) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 15 is a real `memcpy` sink that attempts to copy `INT_MAX` bytes from `first` into `buf`, while `buf` is only 256 bytes as declared on lines 10-11. The only visible guard on line 14 is not an adequate defense because its arithmetic overflows `int`, and no valid bounds check or safer copy is visible before the sink.

## Data flow

std::numeric_limits<int>::max() (line 8) → first_len (line 8) → copy length argument to memcpy (line 15); buf_len = 256 (line 10) → char buf[buf_len] destination buffer (line 11) → memcpy destination (line 15)

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 15: `memcpy(buf, first, first_len);`. The construct described by the rule is present: a `memcpy` call copies `first_len` bytes into destination buffer `buf`.
2. Step 1: No potentially dangerous data originates from user input, file, network, or database in the provided context. The relevant values are compile-time constants: `first_len` is `std::numeric_limits<int>::max()` on line 8, `second_len` is `256` on line 9, and `buf_len` is `256` on line 10.
3. Step 2: Data flow is: `std::numeric_limits<int>::max()` → `first_len` on line 8 → used as the size of `first` on line 11 and as the copy length in `memcpy(buf, first, first_len)` on line 15. Separately, `buf_len = 256` on line 10 → `char buf[buf_len]` on line 11 → destination buffer in the line 15 `memcpy`.
4. Step 3: The only visible check is the `if constexpr ((first_len + second_len) <= buf_len)` guard on line 14. It is not a reliable runtime validation of attacker input; it is a compile-time condition. Also, the expression `first_len + second_len` overflows `int` in standard C++, so the guard itself is not a valid/sufficient bounds check for the flagged copy.
5. Step 4: The sink is line 15: `memcpy(buf, first, first_len);`. The dangerous operation is copying `first_len` bytes, where `first_len` is `INT_MAX` from line 8, into `buf`, which is only 256 bytes from lines 10-11.
6. Step 5: No framework or library automatic protection is visible. `memcpy` is a raw C memory-copy operation and does not perform destination bounds checking.
7. Step 6: The provided context only shows `main` at line 7. No authentication, privilege checks, or caller context are visible. If this program runs, triggering `main` requires only executing the program; no attacker-controlled input path is shown.
8. Step 7: If the flagged copy were executed, the concrete impact would be a stack buffer overflow of `buf` on line 15, potentially causing memory corruption, crash/DoS, or possibly code execution depending on environment. However, no attacker control over the copied contents or length is visible in the provided code.
9. Step 8: The weakest link is the invalid/inadequate size guard on line 14: it attempts to compare combined lengths to `buf_len`, but `first_len + second_len` overflows `int`. There is no visible valid bounds check ensuring `first_len <= buf_len` before line 15.
