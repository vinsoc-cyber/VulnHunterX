# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The reported CWE-697 issue is specifically md5 loose equality, but the flagged loose comparison on line 22 compares a row count to integer `1`. The only md5 value is created on line 16 and used in the SQL query on line 19, with no visible path into a PHP `==` comparison. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Specific defense / non-exploitability condition observed: the flagged comparison on line 22 is `mysqli_num_rows($result) == 1`. Its left operand is the integer-like row count returned by `mysqli_num_rows($result)`, and its right operand is integer literal `1`; neither operand is `$pass`, `md5(...)`, nor a database-provided md5 string. The md5 value is assigned to `$pass` on line 16 and then used only in the SQL string on line 19.
2. (b) Why this covers all reachable paths to the reported sink: within the provided code, the only md5-producing operation is `$pass = md5($pass)` on line 16. The data then flows into `$query` on line 19 and `mysqli_query(...)` on line 20. The flagged loose comparison on line 22 receives `$result` from line 20 only as an argument to `mysqli_num_rows($result)`, not the md5 hash. No alternate assignment or branch in the provided code routes `$pass` or `md5($pass)` into the line 22 `==` comparison.
3. (c) Why the SAST tool flagged this finding: the rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for loose comparisons involving md5 values because PHP type juggling can make hashes like `0e...` compare equal numerically. The visible flagged line 22 does contain a loose comparison operator `==`, but it does not compare md5-derived data. The observed non-exploitability condition is directly checking the rule’s required construct: whether an md5 value reaches the loose comparison. In this snippet, it does not.
4. Step 1: The potentially dangerous data for this rule would originate from user input in `$_GET['password']` on line 13.
5. Step 2: Data flow is `$_GET['password']` line 13 → `$pass` line 13 → `stripslashes($pass)` line 14 → `mysqli_real_escape_string(..., $pass)` line 15 → `md5($pass)` line 16 → SQL query string line 19 → `mysqli_query(...)` line 20. The md5 value does not flow into line 22.
6. Step 3: `stripslashes` on line 14 and `mysqli_real_escape_string` on line 15 are not sufficient defenses for md5 loose equality, but that is not decisive here because no md5 value is compared with `==` in the provided code.
7. Step 4: The sink required by the reported vulnerability would be a loose comparison involving an md5 value. The only visible loose comparison at the flagged line is `mysqli_num_rows($result) == 1` on line 22, which is not an md5 comparison.
8. Step 5: No framework/library automatic protection against md5 loose equality is visible. The CSRF check on line 5 is unrelated to the reported md5 loose-equality issue.
9. Step 6: The path is reachable when `isset($_GET['Login'])` is true on line 3. It appears to be an unauthenticated login path, with an anti-CSRF token check on line 5; caller/session setup is not visible.
10. Step 7: The impact of a real md5 loose-equality issue would be authentication bypass via PHP type juggling. That impact is not shown here because the md5 hash is used in SQL on line 19, not in a PHP loose comparison.
11. Step 8: The weakest-link analysis for the reported rule is that the required vulnerable construct is absent. The line 22 `==` comparison is loose, but it compares a row count to `1`, not an md5 value.
