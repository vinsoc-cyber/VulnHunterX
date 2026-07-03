# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The reported construct is present: `memcpy` on line 9 uses `first_len`, which is `INT_MAX`, as the copy length while the destination `buf` is only 256 bytes. The only visible bounds check on line 8 is inadequate because the `int` addition `first_len + second_len` overflows before the comparison, so there is no reliable visible defense against the buffer overflow.

## Data flow

std::numeric_limits<int>::max() (line 2) → first_len (line 2) → array declaration first[first_len] and buf[buf_len] with buf_len = 256 (lines 4-5) → overflow-prone check (first_len + second_len) <= buf_len (line 8) → memcpy(buf, first, first_len) copies INT_MAX bytes into 256-byte buf (line 9)

## Answers

1. Step 1: The potentially dangerous size value originates from compile-time constants, not from user/file/network/database input visible in the provided context. Specifically, `first_len` is set to `std::numeric_limits<int>::max()` on line 2, `second_len` is set to 256 on line 3, and `buf_len` is set to 256 on line 4.
2. Step 2: Data flow: `std::numeric_limits<int>::max()` on line 2 is assigned to `first_len`; `256` on line 3 is assigned to `second_len`; `256` on line 4 is assigned to `buf_len`; arrays `first`, `second`, and `buf` are declared using those lengths on line 5; `first_len + second_len` is used in the conditional bounds check on line 8; `first_len` is then used as the byte count in `memcpy(buf, first, first_len)` on line 9; `first_len` is also used in pointer arithmetic in `buf + first_len` on line 10.
3. Step 3: The only visible validation is the conditional check `(first_len + second_len) <= buf_len` on line 8. This is not sufficient for the buffer-overflow vulnerability because `first_len + second_len` overflows the range of `int` when `first_len` is `INT_MAX` and `second_len` is 256. Therefore, the check does not reliably prove that the following `memcpy` operations fit within `buf`.
4. Step 4: The sinks are the `memcpy` calls on lines 9 and 10. The immediately flagged dangerous operation is `memcpy(buf, first, first_len)` on line 9, which attempts to copy `INT_MAX` bytes into `buf`, whose size is only 256 bytes as declared on lines 4-5. The second `memcpy` on line 10 is also dangerous because `buf + first_len` points far beyond the 256-byte buffer.
5. Step 5: No framework or library-level automatic protection is visible in the provided context. `memcpy` is a raw C/C++ memory operation and does not perform destination bounds checking.
6. Step 6: The code is in `main` on line 1. No authentication, privilege checks, or caller constraints are visible in the provided context. If the program is executed, this path is reached directly subject to the compile-time conditional behavior.
7. Step 7: If executed, the concrete security impact is memory corruption from an out-of-bounds write/read via `memcpy`, potentially causing denial of service or arbitrary memory corruption. Because no attacker-controlled input is visible, attacker control over exploit details is not established from this snippet alone.
8. Step 8: The weakest link is the attempted bounds check on line 8: it performs `first_len + second_len` using `int`, which overflows before comparison with `buf_len`. This invalidates the defense, allowing the subsequent `memcpy` on line 9 to use a byte count far larger than the destination buffer.
