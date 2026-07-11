# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged sink is exactly present at line 15 and copies `first_len` bytes, where `first_len` is `INT_MAX`, into `buf`, which is only 256 bytes. The only visible guard at line 14 is not an adequate bounds check because `first_len + second_len` overflows signed `int`, so no valid protection against the overflow at line 15 is shown.

## Data flow

std::numeric_limits<int>::max() (line 8) → const int first_len (line 8) → memcpy length argument (line 15); buf_len = 256 (line 10) → char buf[buf_len] (line 11) → memcpy destination buf (line 15)

## Answers

1. Step 1: The flagged line is present at line 15: `memcpy(buf, first, first_len);`, and it contains the reported unsafe copy construct. The potentially dangerous copy length originates from a compile-time constant, `first_len`, initialized to `std::numeric_limits<int>::max()` at line 8. No user, file, network, or database input is visible in the provided context.
2. Step 2: Data flow is: `std::numeric_limits<int>::max()` at line 8 → assigned to `const int first_len` at line 8 → used as the size of `first` at line 11 → used as the third argument to `memcpy` at line 15. Separately, `buf_len` is set to 256 at line 10 → used to declare `buf[buf_len]` at line 11.
3. Step 3: The only apparent check is the `if constexpr ((first_len + second_len) <= buf_len)` condition at line 14. However, with `first_len == INT_MAX` and `second_len == 256`, `first_len + second_len` overflows signed `int`; in standard C++, that is not a valid constant expression. No valid bounds check, sanitization, or safe clamping is visible before the `memcpy` at line 15.
4. Step 4: The sink is `memcpy(buf, first, first_len);` at line 15. It is dangerous because `buf` has size 256 from lines 10-11, while the requested copy length is `first_len`, i.e. `INT_MAX`, from line 8.
5. Step 5: No framework or library-level automatic protection is visible. `memcpy` performs raw memory copying and does not check destination capacity.
6. Step 6: The code is in `main` at line 7. No authentication or privilege boundary is visible. If a compiled binary containing this path were executed, no attacker-controlled authentication state is shown as required.
7. Step 7: If this path executes, the concrete impact is memory corruption from writing far beyond `buf[256]`, likely causing denial of service and potentially arbitrary code execution depending on platform and exploitability. However, no attacker-controlled input affecting the length or contents is visible.
8. Step 8: The weakest link is the invalid/unsafe bounds check at line 14: it attempts to compare `first_len + second_len` against `buf_len`, but the addition overflows signed `int`. There is no visible complete defense that ensures `first_len <= sizeof(buf)` before line 15.
