# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The reported vulnerability class is md5 loose equality/type juggling, but the flagged line compares a database row count to integer `1`, not an md5 hash. The md5 output is used in a SQL predicate, and no PHP loose comparison involving that md5 value is visible. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense/mechanism: there is no md5 loose-equality sink on the flagged line. The md5 value is created at line 27 as `$pass = md5($pass);`, but the flagged loose comparison at line 41 is `mysqli_num_rows($result) == 1`, whose operands are a database row count and integer literal `1`, not the md5 value.
2. (b) Coverage of reachable paths to the reported sink: within the provided code, `$pass` flows from `$_POST['password']` on line 24 through `stripslashes` on line 25, `mysqli_real_escape_string` on line 26, and `md5` on line 27, then into the SQL string on line 39 and `mysqli_query` on line 40. The next loose comparison on line 41 checks only `mysqli_num_rows($result) == 1`; no visible reachable path sends the md5 value into a PHP `==` or `!=` comparison.
3. (c) Why the SAST tool flagged this: the rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for md5-derived values compared using loose equality, because PHP type juggling can make magic hashes such as `0e...` compare equal. In this code, the visible loose equality at line 41 is not checking an md5 value; it checks the number of rows returned by the SQL query. The cited mechanism is therefore not an external sanitizer but the absence of the reported construct at the flagged line.
