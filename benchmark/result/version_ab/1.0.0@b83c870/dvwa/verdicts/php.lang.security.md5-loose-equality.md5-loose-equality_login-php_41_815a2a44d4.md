# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and contains `==`, but the operands are a mysqli row count and integer literal `1`, not an md5 hash. The md5-derived password is used inside the SQL query on line 39; no reachable path in the shown code compares that md5 value with PHP loose equality. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense/benign mechanism: The flagged line is line 41: `if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...`. The loose comparison is present, but it compares `mysqli_num_rows($result)` to integer literal `1`; it does not compare an md5 hash or attacker-controlled hash-like string. The md5 value is created at line 27 and placed into the SQL string at line 39, not compared with `==` in PHP.
2. (b) Why this covers all reachable paths to the flagged sink: The sink expression on line 41 is syntactically fixed in the provided code: `$result && mysqli_num_rows($result) == 1`. `$result` is assigned immediately before from `mysqli_query(...)` on line 40. Every execution reaching line 41 within the shown path uses that same expression and compares only the database result row count to `1`; there is no alternate assignment or branch in the snippet where the md5 value from line 27 becomes an operand of the loose equality on line 41.
3. (c) Why the SAST tool flagged this: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5-derived values, because PHP `==` can type-juggle strings such as magic hashes. The rule likely associated the earlier `md5($pass)` on line 27 with the login check and noticed the loose `==` on line 41. However, the observed line-level evidence shows the `==` is checking `mysqli_num_rows($result) == 1`, not comparing md5 output; therefore the cited benign mechanism directly addresses the rule condition.
