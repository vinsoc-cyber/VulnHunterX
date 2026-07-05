# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/low.php:15

**Verdict:** FP · **Confidence:** High (0.94) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and the rule’s specific construct is absent: line 15 has a loose comparison, but not one involving an md5 value. The md5 output from line 9 flows into the SQL query on line 12, not into the loose comparison on line 15. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. Step 0 / flagged line location: The flagged line is line 15: `if( $result && mysqli_num_rows( $result ) == 1 ) {`. The line contains a loose comparison `==`, but the operands are `mysqli_num_rows($result)` and integer literal `1`; there is no `md5(...)` call or md5 hash variable on this line.
2. Step 1: The potentially relevant md5 data originates from user input `$_GET['password']` on line 8. `$_GET['username']` on line 5 is also user-controlled, but it is not relevant to the reported md5-loose-equality rule.
3. Step 2: Password flow: `$_GET['password']` is assigned to `$pass` on line 8 → `$pass` is transformed by `md5($pass)` on line 9 → the md5 string is interpolated into the SQL query on line 12 as `password = '$pass'` → the query is executed by `mysqli_query(...)` on line 13. The data does not flow to the flagged loose comparison on line 15.
4. Step 3: There is no validation, sanitization, or encoding relevant to md5 loose equality. `md5($pass)` on line 9 hashes the password but is not a type-juggling defense. However, no md5 value is compared using `==` in the provided code.
5. Step 4: For the reported rule, the unsafe sink would be a loose comparison involving an md5 value, for example `md5($input) == $stored_hash`. The only visible loose comparison is line 15, `mysqli_num_rows($result) == 1`, which compares a database row count to `1`, not an md5 value.
6. Step 5: No framework or library automatic protection is visible. The code uses raw `mysqli_query` on line 13. For this specific rule, the relevant issue is absent because the md5 value from line 9 is not used in the loose comparison on line 15.
7. Step 6: The code path is reachable when `isset($_GET['Login'])` is true on line 3. Based on the provided code, this appears reachable by an unauthenticated requester who can supply GET parameters.
8. Step 7: For md5 loose equality specifically, no concrete security impact is demonstrated because no md5 hash is compared with `==`. Other vulnerabilities may exist in this snippet, but they are outside the scope of this rule.
9. Step 8: The weakest-link analysis for this rule is that Semgrep appears to have matched a nearby loose equality in code that also contains `md5()`. The loose comparison on line 15 is not on the md5 value from line 9.
10. (a) Specific defense observed: No defensive check is being cited. Instead, this is a rule-scope/non-match false positive: the flagged construct required by the rule is absent at line 15. The exact mechanism is that line 15 compares `mysqli_num_rows($result)` to integer literal `1`, while the md5 value `$pass` is produced on line 9 and used in the SQL string on line 12, not in the line-15 comparison.
11. (b) Why that covers all reachable paths to the sink: All visible paths to line 15 go through the single `if( isset($_GET['Login']) )` block starting on line 3, and line 15’s expression is fixed as `$result && mysqli_num_rows($result) == 1`. There is no alternate visible branch where `$pass` or `md5($pass)` becomes an operand of the line-15 `==` comparison.
12. (c) Why the SAST tool flagged this: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for comparisons involving md5 values using loose equality `==`, which can cause PHP type juggling issues. The code contains `md5($pass)` on line 9 and a loose comparison on line 15, so the tool likely associated them imprecisely. The observed fact at line 15 is not a defense against md5 loose comparison; rather, it shows the rule’s required md5-comparison pattern is not actually present at the flagged line.
