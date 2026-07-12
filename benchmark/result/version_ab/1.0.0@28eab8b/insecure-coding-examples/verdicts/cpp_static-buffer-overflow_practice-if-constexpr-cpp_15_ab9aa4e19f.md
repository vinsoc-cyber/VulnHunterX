# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** Medium (0.72) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged sink on line 15 does describe a dangerous `memcpy` size, but the path is inside an `if constexpr` whose condition performs signed constant-expression overflow on line 14, making the code ill-formed under conforming C++ rather than an exploitable runtime path. Additionally, the provided context shows only constants and no attacker-controlled source.

## Data flow

constant `std::numeric_limits<int>::max()` assigned to `first_len` (line 8) → `first_len` used as array bound for `first` (line 11) and in overflowing `if constexpr` condition (line 14) → `first_len` used as `memcpy` byte count into 256-byte `buf` (line 15)

## Answers

1. Step 1: The flagged line is present at line 15: `memcpy(buf, first, first_len);`. The dangerous size originates from the compile-time constant `first_len`, initialized to `std::numeric_limits<int>::max()` on line 8. No user, file, network, or database input is visible in the provided context.
2. Step 2: Data flow is: `first_len` is assigned `INT_MAX` on line 8 → used as the bound for `first` on line 11 → used in the `if constexpr` condition on line 14 as part of `first_len + second_len` → used as the byte count argument to `memcpy` on line 15. `buf_len` is assigned 256 on line 10 → used as the bound for `buf` on line 11.
3. Step 3: The only visible check is the `if constexpr ((first_len + second_len) <= buf_len)` on line 14. However, `first_len` is `INT_MAX` and `second_len` is 256, so `first_len + second_len` overflows signed `int` in a constant expression. In standard C++, that is not a valid constant expression, so this does not function as a valid runtime bounds check. No other sanitization or bounds validation is visible.
4. Step 4: The sink is line 15: `memcpy(buf, first, first_len);`. The dangerous operation is copying `first_len` bytes, i.e. `INT_MAX`, into `buf`, which is declared with only 256 bytes on line 11.
5. Step 5: No framework protection is involved. The library call is raw C `memcpy`, which performs no bounds checking. The relevant language feature is `if constexpr` on line 14, whose condition must be a valid constant expression; because the signed addition overflows, conforming C++ compilation should reject this code rather than produce a reachable runtime sink.
6. Step 6: No attacker-controlled entry point or authentication state is visible. The code is in `main` at line 7 and uses only constants. Based only on this context, there is no visible unauthenticated, authenticated, or admin attacker input path.
7. Step 7: If line 15 were compiled and executed despite the invalid constant expression, the concrete impact would be a stack buffer overflow/memory corruption or denial of service by writing far beyond the 256-byte `buf`. However, no attacker control over the source bytes or size is visible, and standard C++ compilation should fail before runtime.
8. Step 8: The weakest link in the apparent defense chain is the attempted bounds check on line 14, because `first_len + second_len` overflows signed `int`. However, that same overflow occurs in an `if constexpr` constant expression, making the program ill-formed in conforming C++, which prevents the flagged `memcpy` from becoming a reachable runtime operation.
