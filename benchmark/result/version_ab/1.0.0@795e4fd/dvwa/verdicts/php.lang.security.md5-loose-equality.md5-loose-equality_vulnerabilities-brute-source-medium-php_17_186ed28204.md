# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and contains `==`, but the compared value is `mysqli_num_rows($result)`, not an md5 hash. Under the reported rule scope, this is a false positive because the md5-loose-equality construct is absent on the flagged path. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: No sanitizer/guard defense is being relied on for the verdict. Instead, the rule's required construct is absent at the flagged line. The flagged line 17 is exactly: `if( $result && mysqli_num_rows( $result ) == 1 ) {`. This is a loose comparison, but it compares `mysqli_num_rows($result)` to integer `1`; it does not compare an md5 value.
2. (b) Why that covers all reachable paths to the sink: For the reported md5-loose-equality sink, there is no reachable PHP loose comparison involving the md5 value in the provided code. The password flows from `$_GET['password']` on line 9 → `mysqli_real_escape_string` on line 10 → `md5($pass)` on line 11 → SQL string on line 14 → `mysqli_query` on line 15. The only visible loose comparison is line 17, and its operands are `$result && mysqli_num_rows($result)` and `1`, not `$pass` or `md5(...)`.
3. (c) Why the SAST tool flagged this finding: The rule looks for comparisons involving md5 values using loose equality `==` instead of strict equality `===`, due to PHP type-juggling / magic-hash risks. The nearby code contains an md5 call on line 11 and a loose equality operator on line 17, so the tool likely associated them. However, the line 17 comparison is a database row-count check, not an md5 comparison. Therefore there is no defense checking md5 equality; rather, the reported rule pattern is not actually present at the flagged line.
