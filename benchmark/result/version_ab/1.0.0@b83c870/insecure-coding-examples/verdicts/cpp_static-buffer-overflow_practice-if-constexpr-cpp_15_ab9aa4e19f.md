# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged sink is a raw `memcpy` at line 15 copying `first_len` bytes into a 256-byte stack buffer, and the only visible guard at line 14 is not an adequate bounds check because the signed addition overflows before comparison. No visible sanitization, clamping, or bounds-checked API prevents the oversized copy from reaching the sink.

## Data flow

constant `std::numeric_limits<int>::max()` initializes `first_len` (line 8) → `first_len` used in overflowing guard expression `first_len + second_len` (line 14) → `first_len` passed as memcpy length (line 15) → destination `buf` has size 256 from `buf_len` (lines 10-11)

## Answers

1. Step 0 / location check: The flagged line is present at line 15 and its exact text is `memcpy(buf, first, first_len);`. This is a `memcpy` into `buf`, and `buf` is declared with size 256 at line 11 via `char first[first_len], second[second_len], buf[buf_len];` with `buf_len = 256` at line 10.
2. Step 1: There is no visible external source such as user input, file, network, or database. The dangerous copy length originates from the constant `first_len`, initialized to `std::numeric_limits<int>::max()` at line 8.
3. Step 2: Data flow is: `std::numeric_limits<int>::max()` at line 8 initializes `first_len`; `first_len` is used as the size of `first` at line 11; `buf_len = 256` at line 10 defines the destination buffer size at line 11; `first_len` is checked in the `if constexpr` expression at line 14; then `first_len` is passed as the third argument to `memcpy` at line 15.
4. Step 3: The only visible validation is the condition `if constexpr ((first_len + second_len) <= buf_len)` at line 14. It is not sufficient because `first_len` is `INT_MAX` at line 8 and `second_len` is 256 at line 9, so the addition `first_len + second_len` overflows a signed `int` before the comparison. No clamp, bounds-safe copy, or separate non-overflowing check is visible.
5. Step 4: The sink is `memcpy(buf, first, first_len);` at line 15. The dangerous operation is copying `first_len` bytes, effectively `2147483647`, into `buf`, which has only 256 bytes as established by lines 10-11.
6. Step 5: No framework or library-level automatic protection is visible. `memcpy` is a raw C library memory-copy primitive and does not perform destination bounds checking.
7. Step 6: No authentication or privilege boundary is visible in the provided code. The code is in `main` at line 7, so if the program is built and run, this path would be triggered by executing the program rather than by a particular authenticated user action.
8. Step 7: If triggered, the concrete impact is stack buffer overflow / memory corruption because line 15 copies far more than the 256-byte destination buffer can hold. Depending on build/runtime mitigations and environment, this could cause denial of service and potentially arbitrary code execution.
9. Step 8: The weakest link is the attempted bounds check at line 14: it performs an overflowing signed addition before comparing against `buf_len`. Because that guard is not a valid safe bounds check, the oversized length reaches `memcpy` at line 15.
