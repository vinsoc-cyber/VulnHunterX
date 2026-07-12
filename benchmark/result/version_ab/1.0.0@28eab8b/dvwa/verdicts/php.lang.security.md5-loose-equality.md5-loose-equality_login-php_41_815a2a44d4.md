# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line does contain `==`, but it compares a MySQL result row count to the integer `1`, not an MD5 hash. The MD5 value from line 27 is used in the SQL predicate on line 39, so the specific md5-loose-equality condition is absent at the flagged sink. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense / disproving condition: line 41 is exactly `if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...`. The loose comparison exists, but its operands are `mysqli_num_rows($result)` and integer literal `1`; no MD5 value is an operand. The MD5 value is created at line 27 as `$pass = md5( $pass );` and then used only in the SQL string at line 39, not in a PHP `==` comparison.
2. (b) Why this covers all reachable paths to the flagged sink: the flagged sink expression on line 41 is syntactically fixed in the provided code. Every path reaching line 41 must first execute the query on line 40, and line 41 always compares the query row count from `mysqli_num_rows($result)` to `1`. There is no alternate branch in the provided context where `$pass` or another MD5 value is compared with `==` at line 41.
3. (c) Why the SAST tool flagged this: the rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons involving MD5 values because PHP type juggling can make certain hashes such as `0e...` compare equal numerically. The rule appears to have associated the earlier `md5($pass)` on line 27 with the later loose comparison on line 41, but the comparison on line 41 is not checking the MD5 hash; it is checking whether the SQL query returned exactly one row.
