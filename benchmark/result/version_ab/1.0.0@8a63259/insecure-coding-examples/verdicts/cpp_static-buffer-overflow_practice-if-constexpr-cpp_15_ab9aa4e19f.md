# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** Medium (0.72) · **Truth:** real · **Grade:** MISS · **Iterations:** 1

## Reasoning

The flagged line 15 does contain a `memcpy` that would copy `INT_MAX` bytes into a 256-byte buffer, but the only visible path to it is guarded by an `if constexpr` condition on line 14 whose signed constant addition overflows and is therefore not a valid C++ constant expression. In conforming C++, the code is ill-formed and no executable runtime path reaches the reported buffer-overflow sink.

## Data flow

std::numeric_limits<int>::max() (line 8) → const int first_len (line 8) → if constexpr bounds expression using first_len + second_len (line 14) → memcpy length argument first_len in memcpy(buf, first, first_len) (line 15); destination buf is char buf[256] from buf_len (lines 10-11)

## Answers

1. Step 0 / Step 1: The flagged line is present at line 15: `memcpy(buf, first, first_len);`. This is the construct described by the rule: a `memcpy` into `buf`. The potentially dangerous copy length originates from a compile-time constant, `first_len`, initialized to `std::numeric_limits<int>::max()` on line 8. No user input, file, network, or database source is visible in the provided context.
2. Step 2: Data flow is: `std::numeric_limits<int>::max()` on line 8 → assigned to `const int first_len` on line 8 → used as the size of `first` on line 11 → used in the `if constexpr` condition on line 14 → used as the copy length argument to `memcpy(buf, first, first_len)` on line 15. Separately, `buf_len = 256` on line 10 → used to declare `char buf[buf_len]` on line 11.
3. Step 3: The only visible validation is the guard `if constexpr ((first_len + second_len) <= buf_len)` on line 14. However, `first_len` is `INT_MAX` and `second_len` is `256`, so `first_len + second_len` overflows signed `int`. In standard C++, that expression is not a valid constant expression for `if constexpr`, so conforming compilation fails before runtime. If it were somehow evaluated with wrapping semantics, the guard would not be a sufficient bounds check.
4. Step 4: The sink is `memcpy(buf, first, first_len)` on line 15. The dangerous operation is copying `first_len` bytes, where `first_len` is `INT_MAX`, into `buf`, which is declared with only 256 bytes on line 11.
5. Step 5: No framework-level or library-level automatic protection is visible. `memcpy` itself provides no bounds checking. The relevant protection visible in the provided code is the C++ language requirement that `if constexpr` use a valid constant expression; the overflowing signed addition on line 14 prevents a conforming executable from being produced.
6. Step 6: No authentication or privilege boundary is visible. The code is in `main` at line 7, so if a binary existed, execution of the program would trigger this path. However, in conforming C++, the shown code is ill-formed because of the overflowing constant expression on line 14.
7. Step 7: If an attacker could somehow cause execution of line 15 in a non-conforming build where the guard is accepted, the impact would be memory corruption or denial of service, potentially worse depending on surrounding runtime conditions. In the provided conforming C++ context, there is no visible attacker-controlled data and no valid runtime path to the sink.
8. Step 8: The weakest link would be the invalid bounds check on line 14, because it performs overflowing signed integer arithmetic. However, for the specific reported static buffer overflow at line 15, the C++ `if constexpr` constant-expression requirement prevents reaching that `memcpy` in a conforming build; there is no complete runtime defense, but there is also no valid runtime execution path shown.
