# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged line is a real oversized `memcpy` pattern in isolation, but the only visible path to it is inside an `if constexpr` whose condition requires evaluating `INT_MAX + 256`, which is not a valid C++ constant expression due signed overflow. Therefore, in standard C++ this code is ill-formed and the dangerous runtime copy is not reachable as an executable path.

## Data flow

constant std::numeric_limits<int>::max() (line 8) → first_len used as array bound for first (line 11) and memcpy length (line 15); buf_len = 256 (line 10) → buf[256] declaration (line 11); attempted guard `(first_len + second_len) <= buf_len` (line 14) is ill-formed in standard C++ due signed overflow → sink `memcpy(buf, first, first_len)` (line 15)

## Answers

1. Step 1 / locate flagged line: The flagged line 15 is exactly `memcpy(buf, first, first_len);`, and it does contain the reported `memcpy` construct. The potentially dangerous size does not originate from user input, file, network, or database; it originates from the compile-time constant `first_len = std::numeric_limits<int>::max()` on line 8.
2. Step 2: Data flow is: `std::numeric_limits<int>::max()` assigned to `first_len` on line 8; `buf_len` is assigned constant `256` on line 10; `first` and `buf` are declared on line 11 as `char first[first_len]` and `char buf[buf_len]`; line 14 attempts a compile-time guard `(first_len + second_len) <= buf_len`; line 15 passes `buf` as destination, `first` as source, and `first_len` as the byte count to `memcpy`.
3. Step 3: The only visible validation is the `if constexpr ((first_len + second_len) <= buf_len)` condition on line 14. However, `first_len + second_len` adds `INT_MAX + 256`, which overflows signed `int`; in standard C++, this is not a valid constant expression for `if constexpr`, so the code is ill-formed rather than a runtime-validated safe path. No runtime bounds check, clamping, or sanitizer is visible before line 15.
4. Step 4: The sink is line 15, `memcpy(buf, first, first_len);`. In abstract, this would be dangerous because it attempts to copy `2147483647` bytes into `buf`, which is declared with only `256` bytes on line 11.
5. Step 5: No framework protection is involved. The library function `memcpy` provides no automatic bounds checking; it trusts the destination pointer and length supplied by the caller.
6. Step 6: No attacker privilege or authentication state is visible in the provided code. This is `main` at line 7 with only constants; no external attacker-controlled input is shown.
7. Step 7: If this copy were reachable in a compiled program, the concrete impact would be memory corruption, likely stack buffer overflow and/or crash/DoS, because line 15 copies far more bytes than the 256-byte destination from line 11 can hold. However, under standard C++ the `if constexpr` condition on line 14 is ill-formed due signed integer overflow in a required constant expression, so this path should not produce an executable runtime path.
8. Step 8: The weakest link in the apparent defense chain is the attempted size check on line 14, because it performs overflowing signed arithmetic. However, for this exact C++ code, that same overflow occurs inside an `if constexpr` condition, which must be a valid constant expression; standard C++ rejects it at compile time, preventing the flagged `memcpy` path from being executed.
