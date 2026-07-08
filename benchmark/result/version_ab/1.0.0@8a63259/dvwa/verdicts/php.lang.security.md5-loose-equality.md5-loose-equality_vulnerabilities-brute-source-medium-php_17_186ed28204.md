# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and contains loose equality, but it compares `mysqli_num_rows($result)` to `1`, not an md5 value. Under the reported rule scope, this is a false positive because the md5-loose-equality construct is absent from the flagged sink. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: No sanitizer or runtime defense is needed for the reported md5-loose-equality issue because the reported construct is absent at the flagged line. The flagged line 17 is exactly `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The mechanism preventing this specific finding from being valid is that the loose comparison on line 17 compares `mysqli_num_rows($result)` to integer `1`; it does not compare an md5 value or md5-derived variable.
2. (b) Coverage of reachable paths to the sink: The only visible reachable path to the flagged comparison is after `$result` is produced by `mysqli_query(...)` on line 15 and then checked on line 17. On line 17, the compared expression is `mysqli_num_rows($result) == 1`. The md5-derived `$pass` from line 11 flows into the SQL query on line 14 and query execution on line 15, but it does not flow into the loose equality operator on line 17. Therefore, all visible paths to the flagged loose comparison involve a row count, not an md5 hash.
3. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values, because PHP `==` can trigger type juggling issues with hash-like strings. The code does contain `md5($pass)` on line 11 and a loose comparison `==` on line 17, but the loose comparison is not checking the md5 value. The cited mechanism is not an md5-specific validation check; rather, the rule’s required construct is absent on the flagged line.
