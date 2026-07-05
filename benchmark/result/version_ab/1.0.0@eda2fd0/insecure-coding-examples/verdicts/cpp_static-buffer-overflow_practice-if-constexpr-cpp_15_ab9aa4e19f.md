# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged construct is a static buffer overflow: `buf` has size 256 on line 5, but `memcpy` is asked to copy `first_len == INT_MAX` bytes into it on line 9. The only visible defense is the `if constexpr` check on line 8, but it is not adequate because the integer addition used in the check overflows and does not establish that the copy fits.

## Data flow

constant std::numeric_limits<int>::max() assigned to first_len (line 2) → buf_len assigned 256 (line 4) → buf declared as char[256] (line 5) → insufficient overflow-prone guard using first_len + second_len (line 8) → memcpy copies first_len bytes into buf (line 9)

## Answers

1. Step 1: The dangerous value does not originate from user input, file, network, or database in the provided context. It originates from compile-time constants: `first_len` is assigned `std::numeric_limits<int>::max()` on line 2, while `second_len` and `buf_len` are assigned 256 on lines 3-4.
2. Step 2: Data flow: `std::numeric_limits<int>::max()` is assigned to `first_len` on line 2; `buf_len` is assigned 256 on line 4; `buf` is declared with size `buf_len` on line 5; `first_len` is used in the `if constexpr` condition with `second_len` on line 8; `first_len` is then used as the copy length in `memcpy(buf, first, first_len)` on line 9.
3. Step 3: The only visible guard is the `if constexpr ((first_len + second_len) <= buf_len)` check on line 8. This is not a sufficient defense because the expression `first_len + second_len` can overflow `int` given `first_len == INT_MAX` and `second_len == 256`, so it does not reliably prove that `first_len` bytes fit into `buf` of size 256.
4. Step 4: The sink is `memcpy(buf, first, first_len)` on line 9. The dangerous operation is copying `first_len` bytes, i.e. `INT_MAX` bytes, into `buf`, which was declared with size 256 on line 5.
5. Step 5: No framework or library-level automatic protection is visible in the provided context. `memcpy` performs no bounds checking; it trusts the supplied length argument on line 9.
6. Step 6: Authentication or privilege requirements are not visible in the provided context. The code is in `main` on line 1, so the path is triggered by executing the program, but who can execute it is not visible.
7. Step 7: If this code path executes, the concrete impact is memory corruption from a static buffer overflow at line 9, likely causing denial of service and potentially arbitrary memory overwrite depending on runtime conditions. The copied data itself is not attacker-controlled in the shown code.
8. Step 8: The weakest link is the bounds check on line 8: it attempts to prove the combined copy size fits into `buf`, but it performs `first_len + second_len` in `int`, which overflows for the visible constant values and therefore does not provide a valid safety guarantee.
