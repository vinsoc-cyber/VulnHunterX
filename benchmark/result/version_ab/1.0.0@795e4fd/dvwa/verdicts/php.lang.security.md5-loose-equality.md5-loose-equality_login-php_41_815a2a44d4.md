# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and contains `==`, but the rule-specific construct is absent: line 41 compares a row count to integer `1`, not an md5 value. The only md5 value is produced at line 27 and used in the SQL query at line 39, with no visible loose md5 comparison on the reported path. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Flagged line verification: line 41 is exactly `if( $result && mysqli_num_rows( $result ) == 1 ) {    // Login Successful...`. It contains a loose comparison operator `==`, but the operands are `mysqli_num_rows($result)` and integer `1`; no md5 value is compared on this line.
2. (a) Specific defense observed: There is no runtime defense such as a strict md5 comparison on the flagged path. Instead, the reported rule's required dangerous construct is absent at the flagged line: line 41 compares a database row count to `1`, not `md5(...)` or an md5 hash variable to another value.
3. (b) Coverage of reachable paths: All visible paths to line 41 go through query construction at line 39 and query execution at line 40. The md5-derived value `$pass` is computed at line 27 and interpolated into the SQL string at line 39; after that, line 41 only evaluates `$result` and `mysqli_num_rows($result) == 1`. In the provided code, there is no reachable visible path where `$pass` or any md5 value reaches the loose comparison at line 41.
4. (c) Why the SAST tool flagged it: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons involving md5 values because PHP type juggling can make certain md5 strings such as magic hashes compare equal under `==`. The tool likely flagged line 41 because the function contains an md5 computation at line 27 and a loose equality comparison at line 41. However, the loose comparison at line 41 is not checking the md5 value; it is checking a MySQL result row count.
5. Q1: The relevant user-controlled data originates from `$_POST['password']` at line 24. Username also originates from `$_POST['username']` at line 20, but the reported rule concerns md5 values, so the password flow is relevant.
6. Q2: Password flow: `$_POST['password']` line 24 → `stripslashes($pass)` line 25 → `mysqli_real_escape_string(..., $pass)` line 26 → `md5($pass)` line 27 → SQL query string at line 39 → `mysqli_query(...)` at line 40 → row-count comparison `mysqli_num_rows($result) == 1` at line 41.
7. Q3: `stripslashes` at line 25 and `mysqli_real_escape_string` at line 26 are not defenses against md5 type juggling; `md5` at line 27 is a hash operation, not validation. The key point for this finding is that no md5 value is used in the loose comparison at line 41.
8. Q4: The sink for an md5 loose-equality issue would be a loose comparison involving an md5 hash. The visible loose comparison sink is line 41, but it compares `mysqli_num_rows($result)` to `1`, not an md5 value.
9. Q5: No framework or library automatic protection for md5 loose equality is visible. The code uses raw `mysqli_query` at line 40 and a CSRF token check at line 18, but neither is relevant protection for md5 loose equality.
10. Q6: The path is reachable by an unauthenticated user submitting a POST request with `Login`, because the branch begins at line 10 before any login has occurred. A CSRF token is checked at line 18, but authentication is not required to reach the login code.
11. Q7: If an md5 loose-equality bug were present, the impact could be authentication bypass via PHP type juggling. In this snippet, that specific impact is not demonstrated because the md5 value from line 27 is used in SQL at line 39, while line 41 checks only whether one row was returned.
12. Q8: The weakest link for the reported rule would have been a loose comparison of an md5 value, but that link is not present in the provided code. The loose comparison exists at line 41, yet its operands are a database row count and integer `1`.
