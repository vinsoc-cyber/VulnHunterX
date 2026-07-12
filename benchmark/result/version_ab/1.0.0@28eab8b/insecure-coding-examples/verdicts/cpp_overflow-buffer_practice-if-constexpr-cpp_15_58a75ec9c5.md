# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** High (0.85) · **Truth:** real · **Grade:** MISS · **Iterations:** 2

## Reasoning

The flagged sink at line 15 would be a severe overflow if executed, because it copies `INT_MAX` bytes into a 256-byte buffer. However, the only visible path to it is through the `if constexpr` condition on line 14, whose signed-overflowing constant expression is ill-formed in conforming C++, so the vulnerable statement is not reachable in a valid executable program. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 15 and its exact text is `memcpy(buf, first, first_len);`. This is a `memcpy` sink using `first_len` as the byte count and `buf` as the destination.
2. (a) Specific defense observed: line 14 contains `if constexpr ((first_len + second_len) <= buf_len)`. Because this is `if constexpr`, the condition must be a valid compile-time constant expression in standard C++. With `first_len = std::numeric_limits<int>::max()` on line 8 and `second_len = 256` on line 9, the expression `first_len + second_len` overflows signed `int`; signed overflow is not permitted in a C++ constant expression. Therefore, in conforming C++, this prevents the guarded block containing line 15 from being part of a valid executable program.
3. (b) Why the defense covers all reachable paths to the sink: line 15 is syntactically inside the block controlled by the `if constexpr` on line 14, and there is no alternate path to the same `memcpy` shown. Since the only visible path to line 15 goes through the compile-time condition on line 14, and that condition is not a valid constant expression, there is no reachable runtime path to the sink in a conforming C++ build.
4. (c) Why the SAST tool flagged this: the `cpp/overflow-buffer` rule looks for buffer operations where the requested access size can exceed the destination buffer size. Here, `buf` is declared with size 256 via `buf_len` on lines 10-11, while the `memcpy` byte count is `first_len`, initialized to `INT_MAX` on line 8 and used on line 15. The rule correctly identifies the apparent size mismatch at the sink, but it appears not to account for the C++ `if constexpr` constant-expression failure on line 14. The defense is not a normal bounds check proving `first_len <= sizeof(buf)`; it is a language-level compile-time reachability barrier caused by the invalid overflowing constant expression.
