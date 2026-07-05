# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/low.php:15

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The rule-specific dangerous construct is absent: although `md5()` appears on line 9 and `==` appears on line 15, the md5 result does not flow into that comparison. Under the rule-scope requirement, a finding for md5 loose equality is false when the flagged loose comparison is not comparing an md5 value. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense observed: There is no runtime defense such as validation or sanitization for md5 loose equality. Instead, the decisive code fact is that the reported vulnerable construct is absent: the md5 result is assigned to `$pass` on line 9 and then interpolated into SQL on line 12; the flagged loose comparison on line 15 is `mysqli_num_rows($result) == 1`, comparing a database row count to integer `1`, not comparing an md5 value.
2. (b) Coverage of all reachable paths to the sink: Within the provided code, the only reachable PHP loose comparison at the flagged line is line 15. All paths entering the block start at `isset($_GET['Login'])` on line 3, compute `$pass = md5($pass)` on line 9, execute the query on line 13, and then evaluate `mysqli_num_rows($result) == 1` on line 15. There is no alternate shown path where `$pass` or `md5($pass)` reaches a PHP `==` comparison.
3. (c) Why the SAST tool flagged this: The rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose equality comparisons involving md5 values, because PHP type juggling can make certain md5 strings such as magic hashes compare equal under `==`. In this snippet, line 15 does contain loose equality `==`, and line 9 contains `md5()`, so the tool likely associated the function with a nearby loose comparison. However, the check at line 15 is not checking the md5 value; it checks the row count returned by `mysqli_num_rows($result)`.
4. Q1: The relevant source for the reported md5 issue is user-controlled `$_GET['password']`, assigned to `$pass` on line 8. `$_GET['username']` on line 5 is also user-controlled but is not relevant to md5 loose equality.
5. Q2: Password flow: `$_GET['password']` on line 8 → `$pass` on line 8 → `md5($pass)` on line 9 → interpolated into `$query` on line 12 → executed by `mysqli_query(...)` on line 13. It does not flow into the loose comparison on line 15.
6. Q3: No validation, sanitization, or encoding for type-juggling is visible. However, for this specific rule, the required dangerous operation — loose comparison of an md5 value — is not visible.
7. Q4: The apparent flagged sink is line 15, `mysqli_num_rows($result) == 1`. The unsafe operation for this rule would be loose comparison involving an md5 value, but line 15 compares a row count, not the md5 hash.
8. Q5: No framework or library automatic protection relevant to md5 loose comparison is visible. The code uses raw `mysqli_query()` on line 13.
9. Q6: The code appears reachable by an unauthenticated requester who can provide `Login`, `username`, and `password` in `$_GET`, based on lines 3, 5, and 8. No authentication gate is visible before this logic.
10. Q7: The impact of a real md5 loose-equality issue would be authentication bypass through PHP type juggling. In the shown code, that specific impact is not established because the md5 hash is used in SQL on line 12, not in a PHP loose comparison.
11. Q8: The weakest link for the reported rule is the loose comparison operator on line 15, but it is not applied to the md5 data from line 9. Separate SQL injection concerns may exist on line 12, but they are outside this rule’s vulnerability class.
