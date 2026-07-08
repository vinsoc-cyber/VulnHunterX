# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

This is not a case where safety is assumed from missing context or an external defense. The flagged line is visible and the rule's specific construct is absent: line 22 performs loose equality on a database row count, while the md5 value from line 16 is only used in the SQL query on line 19. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: There is no sanitizer/guard defense being relied on. Instead, the rule's required construct is absent at the flagged line. Step 0: the flagged line is line 22: `if( $result && mysqli_num_rows( $result ) == 1 ) {`. This line has loose equality `==`, but the left operand is `mysqli_num_rows($result)`, a row-count expression, and the right operand is integer literal `1`. It is not comparing an md5 value.
2. (b) Why this covers all reachable paths to the sink: For the reported md5-loose-equality sink, the only visible md5 value is produced at line 16: `$pass = md5( $pass );`. That value flows into the SQL query on line 19: `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`, then to `mysqli_query()` on line 20. The flagged loose comparison on line 22 uses `$result` and `mysqli_num_rows($result)`, not `$pass` or `md5(...)`. Therefore, across the visible reachable path, the md5-derived value does not reach the flagged `==` operation.
3. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for comparisons involving md5 values that use loose equality such as `==`, which can trigger PHP type-juggling issues. The visible code contains both an `md5()` call on line 16 and a loose equality operator on line 22, so the tool likely associated the two syntactic features. However, the loose equality on line 22 checks whether `mysqli_num_rows($result) == 1`; it is not checking the md5 output from line 16. No cited defense is checking md5 type-juggling because no md5 loose-comparison sink exists in the provided code.
