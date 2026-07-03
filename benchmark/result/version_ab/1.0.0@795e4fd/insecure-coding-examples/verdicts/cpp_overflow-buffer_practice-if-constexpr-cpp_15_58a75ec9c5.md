# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** Medium (0.72) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged memcpy on line 15 would indeed overflow `buf[256]` if executed, but in the provided standard C++ code the path is not a valid runtime path because the enclosing `if constexpr` condition on line 14 requires a constant expression and `INT_MAX + 256` overflows `int`, making the program ill-formed. No attacker-controlled source is visible; the reported security issue is therefore not clearly exploitable from the shown code.

## Data flow

std::numeric_limits<int>::max() (line 8) → const int first_len (line 8) → overflowing constexpr guard first_len + second_len (line 14) → memcpy size argument first_len copying into buf[256] (lines 11 and 15)

## Answers

1. Step 1 / flagged-line location: The flagged line is present at line 15 and its exact text is `memcpy(buf, first, first_len);`; it is a `memcpy` into `buf` using `first_len` as the byte count, matching the cpp/overflow-buffer construct. The byte count originates from the compile-time constant `first_len` initialized to `std::numeric_limits<int>::max()` on line 8. No user, file, network, or database input is visible.
2. Step 2: Data flow is: `std::numeric_limits<int>::max()` assigned to `const int first_len` on line 8 → `first_len` used as the size of `first` on line 11 → `first_len` also used in the compile-time condition `(first_len + second_len) <= buf_len` on line 14 → `first_len` used as the third argument to `memcpy` on line 15. Separately, `buf_len` is set to 256 on line 10 → `buf` is declared as `char buf[buf_len]` on line 11 → `buf` is the destination on line 15.
3. Step 3: The only apparent validation is the `if constexpr ((first_len + second_len) <= buf_len)` guard on line 14. However, `first_len + second_len` is `INT_MAX + 256`, which overflows `int`; in standard C++, this is not a valid constant expression for `if constexpr`, so the program is ill-formed rather than a runtime-protected copy. No runtime sanitization, bounds clamping, or safe-copy API is visible.
4. Step 4: The sink is `memcpy(buf, first, first_len);` on line 15. The dangerous operation would be copying `2147483647` bytes into `buf`, which is only 256 bytes as declared on line 11.
5. Step 5: No framework-level or library-level automatic protection is visible. `memcpy` performs no bounds checking; it trusts the caller-provided size argument on line 15.
6. Step 6: No attacker authentication or privilege level is visible. The code is in `main` at line 7 and uses compile-time constants only; there is no visible attacker-controlled input needed or accepted.
7. Step 7: If this code were compiled and the `memcpy` executed, the concrete impact would be memory corruption / stack buffer overflow and likely denial of service, with potential code execution depending on platform mitigations. However, under standard C++ semantics, the overflowing constant expression in the `if constexpr` condition on line 14 makes the program ill-formed before runtime.
8. Step 8: The weakest link would be the attempted bounds check on line 14 because it performs overflowing signed integer arithmetic. That means it is not a valid protective runtime check. The reason this is not a clear exploitable vulnerability in the provided standard C++ context is instead that all values are compile-time constants and the `if constexpr` condition is ill-formed due to constant-expression overflow, preventing a conforming executable path to line 15.
