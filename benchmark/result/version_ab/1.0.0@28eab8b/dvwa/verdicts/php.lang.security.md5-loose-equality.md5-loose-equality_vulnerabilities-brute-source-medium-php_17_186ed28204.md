# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and contains a loose comparison, but the comparison is between a result-row count and integer literal `1`, not between md5 values. Since the md5 digest from line 11 is only used in the SQL query on line 14 and never compared with `==`, the reported md5 type-juggling issue is absent at the flagged sink. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense / benign condition observed: line 17 is `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The exact mechanism preventing the reported md5-loose-equality issue is that the loose comparison operand is `mysqli_num_rows($result)`, a database row count, compared to integer literal `1`; no md5 digest is an operand of the `==` comparison. The md5 value is produced on line 11, `$pass = md5( $pass );`, but it is used in SQL string construction on line 14, not in the loose comparison on line 17.
2. (b) Why this covers all reachable paths to the flagged sink: every reachable execution of the flagged sink is the single condition on line 17. The only values compared with `==` at that sink are `mysqli_num_rows($result)` and `1`. The `$pass` md5 value from line 11 flows to `$query` on line 14 and `mysqli_query` on line 15, then the returned `$result` is checked on line 17. The md5 string itself does not reach the `==` operator on line 17 on any path visible in the snippet.
3. (c) Why the SAST tool flagged this: the rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values because PHP type juggling can make magic hashes such as `0e...` compare equal under `==`. The snippet contains an md5 call on line 11 and a loose equality on line 17, so the tool likely associated them. However, the observed condition on line 17 is not checking an md5 value; it is checking whether the query returned exactly one row. Therefore the rule's dangerous pattern is not actually present at the flagged sink.
