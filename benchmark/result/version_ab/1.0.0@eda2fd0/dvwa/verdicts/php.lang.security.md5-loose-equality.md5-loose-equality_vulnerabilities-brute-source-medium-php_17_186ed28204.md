# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The rule reports md5 loose equality, but the flagged `==` on line 17 compares a database row count to integer 1, not an md5 value. The md5-derived `$pass` is used only in the SQL query on line 14 in the provided context, so the specific reported vulnerability construct is absent. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: There is no sanitizer/validation defense for md5 loose equality; instead, the reported construct is not present. The md5 value is created on line 11, but the flagged loose comparison on line 17 is `mysqli_num_rows($result) == 1`, which compares a row count to integer `1`, not an md5 hash.
2. (b) Coverage of reachable paths to the sink: The only visible flow of the md5 value is `$pass = md5($pass)` on line 11 → interpolation into SQL on line 14 → execution by `mysqli_query` on line 15. The visible loose comparison sink on line 17 receives `mysqli_num_rows($result)`, not `$pass` or any md5-derived value. Therefore, all visible reachable paths from the md5 value do not reach a PHP loose-equality comparison.
3. (c) Why the SAST tool flagged this: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for comparisons involving md5 values using loose equality such as `==` instead of strict equality `===`. The code contains both an `md5(...)` call on line 11 and a loose comparison `==` on line 17, but the comparison is not involving the md5 value. The cited reason is not a runtime defense; it is a rule-scope mismatch visible in the provided code.
