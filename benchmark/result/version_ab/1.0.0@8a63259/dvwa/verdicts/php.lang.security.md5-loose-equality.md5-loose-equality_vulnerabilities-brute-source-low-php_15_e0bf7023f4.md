# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/low.php:15

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The reported rule is specifically md5 loose equality, but the flagged line 15 compares a MySQL row count to integer `1`, not an md5-derived value. The md5-derived `$pass` from line 9 flows into the SQL query on line 12 and is not used in the loose comparison on line 15. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line verification: The flagged line is line 15: `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The line contains a loose comparison operator `==`, but the compared expressions are `mysqli_num_rows($result)` and integer literal `1`; no `md5` value, `$pass`, or hash comparison is present on this line.
2. (a) Specific defense observed: No sanitizer or runtime defense is being cited. The basis for the False Positive verdict is narrower: the specific dangerous construct described by the rule is absent at the flagged line. Line 15 does not compare an md5-derived value; it compares a database row count to `1`.
3. (b) Coverage of reachable paths to the sink: For the reported md5-loose-equality sink, there is no reachable md5 loose-comparison sink in the provided code. The only visible md5-derived value is `$pass = md5($pass)` on line 9, and it flows into the SQL string on line 12, not into the loose comparison on line 15. The loose comparison on line 15 is reached after `mysqli_query` on line 13, but its operands are `$result` truthiness and `mysqli_num_rows($result) == 1`; the md5 value does not reach that comparison.
4. (c) Why the SAST tool flagged this finding: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for comparisons involving md5 values using loose equality such as `==`, which can cause PHP type-juggling issues. The tool likely flagged line 15 because it saw a loose equality operator `==` in a function that also computes `md5` on line 9. However, the check on line 15 is not checking an md5 value; it checks whether the query returned exactly one row.
5. Step 1: The potentially relevant user-controlled source for the reported rule is `$_GET['password']` on line 8. There is also `$_GET['username']` on line 5, but username is not relevant to the md5-loose-equality rule.
6. Step 2: Password data flow is: `$_GET['password']` on line 8 → assigned to `$pass` on line 8 → transformed by `md5($pass)` on line 9 → interpolated into `$query` on line 12 → query executed by `mysqli_query(...)` on line 13. The flagged line 15 uses `$result` and `mysqli_num_rows($result)`, not `$pass`.
7. Step 3: For the md5-loose-equality vulnerability type, no validation or sanitization is shown, but no md5 loose-comparison sink is shown either. The `md5` operation on line 9 is a transformation, not a sanitizer. No strict comparison defense such as `===` is present, but the relevant md5 comparison is also absent.
8. Step 4: The sink for the reported issue would be a loose comparison involving an md5 value. The visible loose comparison sink on line 15 is `mysqli_num_rows($result) == 1`, which is not an md5 comparison and therefore is not the unsafe operation described by this rule.
9. Step 5: No framework or library automatic protection for md5 loose equality is visible. The code uses raw `mysqli_query` on line 13. This does not change the md5-loose-equality assessment because the md5 value is not loosely compared in the shown code.
10. Step 6: The code path appears reachable by an unauthenticated requester who can provide `Login` in the query string, based on `isset($_GET['Login'])` on line 3. No authentication guard is visible before this block.
11. Step 7: For the specific reported md5 loose-equality issue, no concrete security impact is demonstrated in this snippet because there is no loose comparison involving the md5 hash. Other possible issues are outside the scope of this rule.
12. Step 8: The weakest link for this specific finding is the rule match itself: the flagged loose comparison exists on line 15, but it is not a comparison involving an md5 value. Therefore the reported vulnerability class is not present at the flagged line.
