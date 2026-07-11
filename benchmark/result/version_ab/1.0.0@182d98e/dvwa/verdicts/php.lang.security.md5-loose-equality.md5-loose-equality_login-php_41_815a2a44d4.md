# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line 41 does contain `==`, but the md5-derived `$pass` from line 27 is not an operand of that comparison; it is used in the SQL query on line 39. All visible paths to line 41 compare the direct result of `mysqli_num_rows($result)` to integer `1`, so the md5 loose-equality vulnerability described by the rule is not present at the flagged sink. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line: Line 41 is `if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...`. The construct present is a loose equality comparison `==`, but the operands are `mysqli_num_rows($result)` and integer literal `1`, not an `md5()` value.
2. (a) Specific observed defense / concrete benign property: The relevant visible mechanism is source/type separation at the flagged sink: the md5 value is created as `$pass = md5( $pass );` on line 27 and then used only inside the SQL string on line 39. At the flagged loose comparison on line 41, the compared value is instead the direct return of `mysqli_num_rows($result)`, where `$result` was assigned from `mysqli_query(...)` on line 40. Thus the md5 digest does not reach the `==` sink.
3. (b) Why this covers all reachable paths to the sink: Within the provided top-level code path, line 41 is reached only after `$result` is assigned by `@mysqli_query(...)` on line 40. There are no alternate assignments to `$result` between lines 40 and 41, and the left operand of `==` is a direct call `mysqli_num_rows($result)` on line 41. Therefore, in all visible paths to this sink, the compared value is a database row count, not the md5 string from line 27.
4. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5-derived values because PHP type juggling can make hashes such as `0e...` compare equal under `==`. In this snippet, the rule likely correlated the earlier `md5($pass)` on line 27 with a later loose comparison on line 41. However, the observed property above is checking the right condition for this rule: whether the md5-derived value actually reaches the loose comparison. It does not; line 41 compares a row count to `1`.
5. Original Q1 source: User-controlled input originates from unauthenticated POST parameters: `$_POST['username']` on line 20 and `$_POST['password']` on line 24.
6. Original Q2 trace: `$user`: line 20 `$_POST['username']` → line 21 `stripslashes` → line 22 `mysqli_real_escape_string` → line 39 SQL query. `$pass`: line 24 `$_POST['password']` → line 25 `stripslashes` → line 26 `mysqli_real_escape_string` → line 27 `md5($pass)` → line 39 SQL query. `$result`: line 40 `mysqli_query(...)` → line 41 `mysqli_num_rows($result) == 1`.
7. Original Q3 validation/sanitization: Lines 22 and 26 apply `mysqli_real_escape_string()` for SQL context. For the reported md5 loose-comparison issue, the important visible fact is not sanitization but non-flow: the md5 digest from line 27 is not compared with `==` at line 41.
8. Original Q4 sink: The reported sink is line 41, `mysqli_num_rows($result) == 1`. The operation is loose equality, but it is a row-count check, not a loose comparison of md5 hashes.
9. Original Q5 framework/library protections: Anti-CSRF is invoked on line 18 and SQL escaping is applied on lines 22 and 26. No ORM or prepared statement is visible. For this specific finding, the decisive protection is that the library row-count result, not the md5 digest, is the operand at line 41.
10. Original Q6 attacker state: The code is reachable by an unauthenticated user submitting a login POST with `Login` set on line 10, subject to the CSRF token check on line 18.
11. Original Q7 impact: For the reported md5 loose-equality issue, no concrete impact is visible because the md5 digest is not used in a PHP loose comparison.
12. Original Q8 weakest link: The weakest-looking construct is the loose `==` on line 41, but the specific dangerous md5 type-juggling data flow is absent. The md5 digest from line 27 goes to the SQL query on line 39, while line 41 compares only `mysqli_num_rows($result)` to `1`.
