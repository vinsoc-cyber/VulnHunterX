# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line 22 contains a loose comparison, but the compared value is `mysqli_num_rows($result)`, not the md5 digest computed on line 16. The visible data flow shows the md5 value is used in the SQL query on line 19 and never reaches the loose equality sink, so the rule-described PHP md5 type-juggling issue is not present at this flagged line. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific observed defense / mechanism: The flagged line is line 22: `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The concrete mechanism preventing the reported md5-loose-equality issue is that the loose comparison operand is `mysqli_num_rows($result)`, a MySQLi row-count API result, compared to integer literal `1`; it is not `$pass`, `md5($pass)`, or any md5 digest string. The md5 value is computed on line 16 and used only to build the SQL string on line 19.
2. (b) Coverage of reachable paths to the sink: The only visible path to the flagged comparison is `$result` assigned from `mysqli_query(...)` on line 20, followed by the condition on line 22. The md5 output from line 16 flows into `$query` on line 19, then into `mysqli_query` on line 20, but the value compared with `==` on line 22 is the row count returned by `mysqli_num_rows($result)`, not the md5 string. Therefore, for the reported sink on line 22, all visible reachable paths compare a library-produced row count to `1`, not attacker-controlled md5 text.
3. (c) Why SAST flagged it: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values because PHP `==` can trigger type juggling, especially with magic hashes like strings beginning with `0e...`. The code contains `md5($pass)` on line 16 and a loose equality operator `==` on line 22, so the tool likely associated the nearby md5 usage with the loose comparison. However, the check on line 22 is not checking the md5 value; it checks `mysqli_num_rows($result) == 1`. The cited mechanism directly addresses the rule’s condition because the md5 digest does not reach the loose comparison.
