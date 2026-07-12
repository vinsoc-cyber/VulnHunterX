# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/low.php:15

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is visible and benign for this rule: line 15 performs loose equality on a row count, not on an md5 hash. Although line 12 appears vulnerable to SQL injection, that is a separate issue and does not make the md5-loose-equality finding at line 15 true. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense / benign condition: line 15 is `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The left operand of `==` is `mysqli_num_rows($result)`, a database result row count, and the right operand is integer literal `1`. The md5 value is created on line 9 as `$pass = md5( $pass );` but is not compared with `==`; it is interpolated into the SQL query on line 12.
2. (b) Coverage of all reachable paths to the flagged sink: the only visible reachable path to line 15 is guarded by `isset($_GET['Login'])` on line 3, then query construction on line 12, query execution on line 13, and the fixed row-count comparison on line 15. Along every visible path to the flagged line, the comparison remains `mysqli_num_rows($result) == 1`; no attacker-controlled md5 string or stored md5 hash is an operand of the loose equality at line 15.
3. (c) Why SAST flagged this: the rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons such as `==` involving md5-derived values because PHP type juggling can make hashes like `0e...` compare equal numerically. The code does contain `md5($pass)` on line 9 and a loose comparison on line 15, so the tool likely associated them imprecisely. However, the comparison actually flagged on line 15 checks only a mysqli row count against `1`; the md5-derived `$pass` from line 9 is used in SQL on line 12, not in the loose comparison.
