# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and the loose comparison exists, but it is a row-count comparison, not an md5-value comparison. This is a rule-scope false positive: the specific CWE-697/md5 type-juggling construct reported by the rule is absent at the flagged line. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: No runtime defense such as validation, sanitization, or framework protection is needed for the reported md5-loose-equality issue because the flagged construct is absent. The flagged line 22 is exactly `if( $result && mysqli_num_rows( $result ) == 1 ) {`; it compares `mysqli_num_rows($result)` to integer `1`, not an `md5` value.
2. (b) Coverage of reachable paths to the sink: The only visible flagged sink for this Semgrep finding is line 22. All visible execution reaching line 22 comes through the query execution on line 20, assigning `$result`, and then evaluating `$result && mysqli_num_rows($result) == 1` on line 22. The value produced by `md5($pass)` on line 16 flows into the SQL string on line 19 and query execution on line 20, but it does not flow into a loose equality comparison with `==` or `!=` in the visible code.
3. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons involving md5 values, because PHP type juggling can make hashes such as `0e...` compare equal numerically. The flagged line 22 does contain loose equality `==`, but the compared expression is `mysqli_num_rows($result) == 1`; the defense/negating fact is not a sanitizer but the absence of an md5-involved comparison at the flagged line. Therefore the rule’s specific dangerous pattern is not present in the cited code location.
