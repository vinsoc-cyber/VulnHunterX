# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and the loose comparison is present, but it is not a comparison involving an md5 value; it is a database row-count check. Under the reported rule scope, this is a false positive because the md5 value generated on line 27 is never loosely compared in PHP in the provided code. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: No positive defense such as sanitization, validation, or strict comparison is needed for the reported md5-loose-equality issue because the rule's required construct is absent at the flagged line. The flagged line is line 41: `if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...`. This contains loose equality `==`, but it compares `mysqli_num_rows($result)` to integer `1`, not an `md5` value.
2. (b) Coverage of reachable paths to the sink: The md5-derived value is created at line 27 with `$pass = md5( $pass );`, then placed into the SQL query at line 39 and executed at line 40. The reachable comparison at line 41 operates only on `$result` and `mysqli_num_rows($result)`. In the provided code, there is no path where `$pass`, `md5($pass)`, or any stored md5 hash reaches a PHP loose equality comparison.
3. (c) Why the SAST tool flagged this: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values, because PHP `==` can type-juggle strings such as `0e...` into numeric zero. The flagged line does contain `==` at line 41, but the operands are `mysqli_num_rows($result)` and `1`; the md5 value from line 27 is not an operand. Therefore, the rule pattern is not actually satisfied at the flagged line.
