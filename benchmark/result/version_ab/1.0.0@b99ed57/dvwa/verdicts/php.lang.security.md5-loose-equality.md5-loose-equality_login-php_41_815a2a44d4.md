# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line does contain `==`, but the comparison is between a database row count and the constant `1`, not between md5 values or attacker-controlled strings. The visible code shows the md5 value is used in the SQL WHERE clause on line 39 and does not reach the PHP loose equality sink on line 41. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense / benign condition: At line 41, the exact flagged code is `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The loose comparison exists, but its operands are the return value of `mysqli_num_rows($result)` and the constant `1`; the md5 value `$pass` from line 27 is not an operand of this comparison.
2. (a) Additional line references for separation from md5: `$pass = md5( $pass );` occurs on line 27, then `$pass` is interpolated into the SQL string on line 39: `password='$pass'`. The query is executed on line 40 and produces `$result`. Line 41 checks only whether the query returned exactly one row.
3. (b) Why this covers all reachable paths to the flagged sink: The flagged sink expression on line 41 has fixed operands in the source code: `$result` and `mysqli_num_rows($result) == 1`. There is no branch or alternate assignment in the provided code that makes the md5 string `$pass` participate in the `==` comparison on line 41. All visible paths to line 41 pass through line 40, where `$result` is assigned from `mysqli_query(...)`, and line 41 then compares only the row count to `1`.
4. (c) Why the SAST tool likely flagged this: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons using `==` in code involving md5-derived values, because PHP type juggling can make magic md5 hashes such as strings beginning with `0e...` compare equal numerically. In this snippet, the rule appears to have matched the `==` operator on line 41 in the login/authentication flow after an md5 hash is computed on line 27.
5. (c) Whether the observed condition actually checks the rule concern: The observed condition is not a sanitizer or runtime check for md5 magic hashes; instead, it shows the rule concern is not present at the flagged sink. The md5 output from line 27 is not loosely compared in PHP. It is used as a quoted SQL value on line 39, while the loose comparison on line 41 is a row-count comparison.
