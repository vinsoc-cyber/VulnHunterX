# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged sink at line 15 copies `first_len` bytes, where `first_len` is `INT_MAX` from line 8, into `buf`, which is only 256 bytes on line 11. The only visible guard on line 14 is inadequate because the signed addition `first_len + second_len` overflows before the bounds comparison, leaving no valid visible protection for the `memcpy`.

## Data flow

std::numeric_limits<int>::max() initializes first_len (line 8) → first_len used as first array size and later copy length (line 11, line 15) → buf_len initializes buf as 256 bytes (lines 10-11) → flawed if constexpr size check using first_len + second_len (line 14) → memcpy copies first_len bytes into 256-byte buf (line 15)

## Answers

1. Step 0 / flagged line: The flagged line is present at line 15 and its exact text is `memcpy(buf, first, first_len);`. The dangerous construct is present: `memcpy` copies `first_len` bytes into `buf`, where `buf` is declared with size 256 on line 11.
2. Step 1: The potentially dangerous copy length originates from a compile-time constant, not from user/file/network/database input. `first_len` is initialized to `std::numeric_limits<int>::max()` on line 8. The source buffer `first` is declared on line 11.
3. Step 2: Data flow: `std::numeric_limits<int>::max()` initializes `first_len` on line 8; `first_len` is used as the array bound for `first` on line 11; `buf_len` is initialized to 256 on line 10 and used as the array bound for `buf` on line 11; `first_len` is used in the `if constexpr` condition on line 14; `first_len` is then passed as the byte count to `memcpy(buf, first, first_len)` on line 15.
4. Step 3: The only visible validation is the `if constexpr ((first_len + second_len) <= buf_len)` check on line 14. This is not sufficient because `first_len` is `INT_MAX` from line 8 and `second_len` is 256 from line 9, so the addition itself exceeds the range of `int`; there is no visible safe-width cast or separate check that `first_len <= buf_len` before line 15.
5. Step 4: The sink is line 15: `memcpy(buf, first, first_len);`. The unsafe operation is copying `first_len` bytes, effectively 2147483647, into `buf`, which has only 256 bytes as declared on line 11.
6. Step 5: No framework or library-level automatic protection is visible. `memcpy` is a raw C library memory-copy routine and does not bounds-check the destination buffer at line 15.
7. Step 6: No authentication or privilege boundary is visible in the provided code. The code is in `main` at line 7, so triggering it appears to require only executing the program; no attacker-controlled input path is shown.
8. Step 7: If this code path executes, the concrete impact is memory corruption from a static buffer overflow at line 15, likely causing denial of service and potentially enabling arbitrary code execution depending on build/runtime mitigations. The provided context does not show attacker control over copied contents, so exploitability beyond crash is not fully demonstrated.
9. Step 8: The weakest link is the flawed size check on line 14: it attempts to validate combined lengths using signed `int` arithmetic but can overflow before comparison, and there is no independent bounds check ensuring `first_len` is at most `buf_len` before the `memcpy` on line 15.
