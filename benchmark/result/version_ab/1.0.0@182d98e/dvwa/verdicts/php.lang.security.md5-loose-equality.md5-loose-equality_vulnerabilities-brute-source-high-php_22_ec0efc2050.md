# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The SAST rule found a loose `==` in a scope containing `md5()`, but the exact flagged line compares a mysqli row count to `1`, not an md5 digest. The provided code shows the md5 value is used in the SQL query on line 19 and does not flow into the loose equality on line 22. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0: The flagged line is line 22: `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The construct present on that line is a loose equality comparison `==`, but the comparison is `mysqli_num_rows($result)` versus integer literal `1`; no `md5()` value is compared on that line.
2. (a) Specific observed defense / reason the flagged sink is not the reported vulnerability: line 22 uses `mysqli_num_rows($result)` as the left-hand operand of `==`, which is a mysqli row-count API call, and compares it to integer literal `1`. The `md5()` value is assigned to `$pass` on line 16 and used only inside the SQL query string on line 19. There is no visible flow from `$pass` or `md5($pass)` into the loose comparison on line 22.
3. (b) Why this covers all reachable paths to the sink: every reachable path to the flagged sink must execute the single expression on line 22. That expression is fixed in the provided code: `$result && mysqli_num_rows($result) == 1`. The only value compared with `==` is the return value of `mysqli_num_rows($result)`, guarded by `$result &&` short-circuiting on the same line. There is no alternate branch or variable assignment in the provided code that can replace the `==` operand with the md5 digest from line 16.
4. (c) Why the SAST tool likely flagged this: the rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons involving or near `md5()` values because PHP type juggling can make strings like `0e...` compare equal numerically. In this snippet, `md5($pass)` exists on line 16 and a loose comparison exists on line 22, but the loose comparison is not checking the md5 digest. The observed defense/reason is directly relevant: the operand at the flagged comparison is a row count, not the md5 value.
5. Source: attacker-controlled input originates from `$_GET['username']` on line 8 and `$_GET['password']` on line 13.
6. Trace: password flows from `$_GET['password']` line 13 → `stripslashes($pass)` line 14 → `mysqli_real_escape_string(..., $pass)` line 15 → `md5($pass)` line 16 → SQL query string line 19 → database query result line 20. Separately, line 22 checks `mysqli_num_rows($result) == 1`; the md5 digest does not flow into that loose equality.
7. Validation/sanitization: `stripslashes` and `mysqli_real_escape_string` are applied on lines 14-15 before hashing and SQL use. For the specific md5-loose-equality issue, the decisive point is not sanitization but non-use: the md5 value from line 16 is not an operand of the `==` on line 22.
8. Sink and impact: the flagged sink is the loose equality operation on line 22. As written, it is a login row-count check, not an md5 loose comparison. Therefore the reported md5 type-juggling impact is not present on the flagged path.
