# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and exactly contains a loose comparison, but the comparison is `mysqli_num_rows($result) == 1`, not an md5 comparison. Since the md5 output from line 11 is only used in the SQL query on line 14 and is not compared with `==`, the flagged sink is present-but-harmless for this rule. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed safety fact/defense: line 17 is `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The loose comparison is between `mysqli_num_rows($result)` and integer literal `1`; the md5 value assigned on line 11 is not an operand of this comparison. The relevant mechanism is that the flagged sink is not an md5-value comparison at all.
2. (b) This covers all reachable paths to the flagged sink because there is only one visible flagged sink at line 17, and its operands are fixed in the provided code: `$result` from `mysqli_query` on line 15 and `mysqli_num_rows($result)` compared to literal `1`. The password md5 value flows from line 11 into the SQL string on line 14, then into `mysqli_query` on line 15; it does not flow into the `== 1` comparison on line 17.
3. (c) The SAST rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons involving md5 values because PHP `==` can type-juggle magic hashes such as `0e...`. The rule likely flagged this file because line 11 computes `md5($pass)` and line 17 contains `==`; however, the visible code shows the `==` on line 17 compares a row count to `1`, not an md5 hash. Therefore, the observed safety fact directly addresses what the rule is supposed to detect.
