# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and contains a loose comparison, but the comparison is of a database row count to integer `1`, not an md5 hash comparison. The md5 output from line 11 is used in the SQL query on line 14, so the specific md5 loose-equality vulnerability is absent on the flagged path. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: line 17 is `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The defense is not an explicit runtime check, but a sink/source/type fact visible at the flagged line: the loose comparison is between `mysqli_num_rows($result)` and integer literal `1`, not between an `md5(...)` value and attacker-controlled input. The md5 value is produced on line 11 and used only in the SQL query string on line 14.
2. (b) This covers all reachable paths to the flagged sink because there is only one flagged sink expression shown on line 17, and its compared operands are fixed in the expression: `mysqli_num_rows($result)` and `1`. `$pass = md5($pass)` on line 11 does not flow into the loose comparison on line 17; it flows into `$query` on line 14 and then into `mysqli_query` on line 15. Therefore, every visible path reaching line 17 compares a result row count, not an md5 hash.
3. (c) The SAST rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values, because PHP type juggling can make hashes like `0e...` compare equal under `==`. The tool likely flagged line 17 because it contains a loose comparison `== 1` in authentication logic after an md5 calculation on line 11. However, the cited defense/source fact is checking the relevant rule condition: the loose comparison on line 17 does not involve the md5 value from line 11.
