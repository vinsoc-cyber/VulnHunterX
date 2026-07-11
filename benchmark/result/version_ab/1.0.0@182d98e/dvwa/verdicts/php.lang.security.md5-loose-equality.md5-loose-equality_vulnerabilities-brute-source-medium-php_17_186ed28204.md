# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and contains loose equality, but the compared expression is `mysqli_num_rows($result) == 1`, not an md5 digest comparison. The md5 output from line 11 flows into the SQL query on line 14 and is never used as an operand to `==` in the provided code. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense / mechanism: The flagged line 17 is `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The mechanism preventing the reported md5-loose-equality issue is that the loose comparison is not performed on an md5 value at all. The left operand is `mysqli_num_rows($result)`, a database row-count API result, and the right operand is the integer literal `1`. The md5 value is produced on line 11 as `$pass = md5( $pass );` and is used in the SQL string on line 14, not compared with `==` in PHP.
2. (b) Why this covers all reachable paths to the flagged sink: In the provided code, every path to line 17 first assigns `$result` from `mysqli_query(...)` on line 15. The only comparison at the flagged sink is `$result && mysqli_num_rows($result) == 1` on line 17. There is no branch or alternate assignment in the visible code that makes `mysqli_num_rows($result)` contain `$pass`, the md5 digest, or another attacker-controlled md5-like string. Therefore, for all visible reachable paths to the flagged sink, the loose equality is a row-count comparison, not an md5 comparison.
3. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for comparisons involving md5 values that use loose equality `==` instead of strict equality `===`, because PHP type juggling can make certain md5 hashes such as numeric-looking strings compare equal unexpectedly. The tool likely associated the earlier `md5($pass)` on line 11 with a later loose comparison on line 17. However, the check on line 17 is not actually checking `$pass` or the md5 output; it is checking `mysqli_num_rows($result) == 1`.
4. Q1: The user-controlled sources are `$_GET['username']` on line 5 and `$_GET['password']` on line 9.
5. Q2: Password flow: `$_GET['password']` line 9 → `mysqli_real_escape_string(...)` line 10 → `md5($pass)` line 11 → SQL query string line 14 → `mysqli_query(...)` line 15. The flagged comparison on line 17 uses `$result` and `mysqli_num_rows($result)`, not the md5 value directly.
6. Q3: Sanitization/validation: line 10 applies `mysqli_real_escape_string` before md5 hashing on line 11. For the specific md5-loose-equality issue, the relevant fact is not sanitization but non-use: the md5 value from line 11 is not compared using `==` at line 17.
7. Q4: The reported sink is line 17, a loose equality comparison `mysqli_num_rows($result) == 1`. This operation would be dangerous for this rule only if an md5 value were one of the operands, which is not the case in the visible code.
8. Q5: No framework or ORM protection is visible; the code uses raw mysqli on line 15. This does not change the md5-loose-equality assessment because the flagged comparison does not involve the md5 digest.
9. Q6: The code path is reachable by an unauthenticated requester who provides `Login` in the query string, based on `isset($_GET['Login'])` on line 3. No authentication guard is visible before this block.
10. Q7: For this specific finding, no md5 type-juggling impact is demonstrated because the md5 value is not loosely compared. The visible code may have other security concerns, but they are outside this finding’s flagged sink.
11. Q8: The weakest alleged link for this rule would be a loose comparison of the md5 digest, but that link is absent. Line 17 has loose equality, yet the operands are row count and integer literal, not md5 data.
