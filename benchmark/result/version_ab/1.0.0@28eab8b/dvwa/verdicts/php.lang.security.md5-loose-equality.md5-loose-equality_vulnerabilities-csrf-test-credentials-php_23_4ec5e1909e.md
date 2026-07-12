# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/csrf/test_credentials.php:23

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line 23 is visible and does contain `==`, but the expression being compared is `mysqli_num_rows($result)`, not the md5 digest created on line 19. All visible paths to the sink use the same row-count comparison, so the specific md5 type-juggling vulnerability described by the rule is absent at the flagged sink. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0: The flagged line is present at line 23: `if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...`. The line contains a PHP loose equality comparison `== 1`, but the compared expression is `mysqli_num_rows($result)`, not an `md5(...)` value or variable holding an md5 digest.
2. (a) Specific observed defense / benign mechanism: The relevant mechanism is visible on line 23 itself: the left-hand side of the loose comparison is `mysqli_num_rows($result)`, a row-count API result, and the right-hand side is integer literal `1`. The md5 digest is computed at line 19 as `$pass = md5( $pass );`, but that value is used only in the SQL string at line 21, not in the loose comparison at line 23.
3. (b) Why this covers all reachable paths to the flagged sink: All visible paths to the flagged sink line 23 go through the same expression `mysqli_num_rows($result) == 1`; there is no branch or alternate assignment that makes line 23 compare `$pass`, `md5($pass)`, a database password hash, or any other hash-like string with `==`. Lines 10-22 build and execute the query, and line 23 always compares only the query result row count to `1`.
4. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values because PHP type juggling can make strings such as `0e...` compare equal. The flagged line likely matched because it contains `==` near code that computes an md5 hash on line 19. However, the observed line-23 comparison is not checking an md5 value at all; it checks whether the SQL result has exactly one row.
5. Source: User-controlled HTTP POST data originates from `$_POST['username']` on line 12 and `$_POST['password']` on line 16.
6. Trace: username flows line 12 → `stripslashes` line 13 → `mysqli_real_escape_string` line 14 → SQL query line 21. Password flows line 16 → `stripslashes` line 17 → `mysqli_real_escape_string` line 18 → `md5($pass)` line 19 → SQL query line 21. Query result flows from `mysqli_query` line 22 → `$result` → `mysqli_num_rows($result) == 1` line 23.
7. Validation/sanitization: `mysqli_real_escape_string` is applied on lines 14 and 18 for SQL-string escaping, and `md5` is applied on line 19. These are not defenses against md5 loose comparison; instead, the key fact for this finding is that the md5 value is not part of the loose comparison on line 23.
8. Sink and impact: The reported sink is the loose comparison on line 23. For the reported md5-loose-equality issue, there is no concrete exploit impact because the sink compares a row count to integer `1`, not an attacker-controlled md5-looking string to another value.
