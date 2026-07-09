# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/medium.php:21

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is a manually constructed SQL string, but the only visible path to it validates `$_GET['user_id']` with a digits-only full-string regex on line 14 before assigning it to `$id` on line 17. Because SQL metacharacters cannot reach the query on lines 21-22 through this path, the specific CWE-89 finding is not exploitable in the provided code.

## Data flow

source `$_GET['user_id']` (line 13) → validation `preg_match('/^\d+$/', $_GET['user_id'])` (line 14) → assignment `$id = $_GET['user_id'];` (line 17) → SQL string construction `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'";` (line 21) → sink `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` (line 22). Additional requested context for `$_GET`, `$GLOBALS["___mysqli_ston"]`, and the full enclosing script was unavailable and does not add another visible path.

## Answers

1. Step 0 / flagged line located: line 21 is exactly `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'";`. The rule's construct is present on that line: a manually constructed SQL string interpolates `$id`. The enclosing function is still not identified; the code context labels it as `Function: <unknown>`.
2. Q1: The potentially dangerous data originates from HTTP GET input: `$_GET['user_id']`, checked for presence on line 13. The additional context for `global:$_GET` is unavailable, so it does not change this answer.
3. Q2: Data flow remains: `$_GET['user_id']` presence check on line 13 → validation by `preg_match('/^\d+$/', $_GET['user_id'])` on line 14 → assignment `$id = $_GET['user_id'];` on line 17 → interpolation into `$check_query` on line 21 → execution by `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` on line 22.
4. Q3: Yes, validation is visible. Line 14 applies a strict allowlist regex, `/^\d+$/`, requiring the entire supplied `user_id` value to consist of one or more digits before execution reaches the assignment on line 17 and the SQL construction on line 21. For CWE-89 SQL injection through this value, this is sufficient in the visible path because quote characters, spaces, operators, comments, and SQL keywords cannot pass this check.
5. Q4: The sink is `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` on line 22. The dangerous operation would be executing the manually constructed query from line 21, but the interpolated value `$id` is constrained by the line 14 numeric allowlist on the shown path.
6. Q5: No automatic framework/library SQL injection protection is visible. The code uses raw `mysqli_query` rather than a prepared statement or ORM on line 22. The additional context for `$GLOBALS["___mysqli_ston"]` is unavailable and does not show any automatic parameterization; the relevant visible protection is the explicit validation on line 14.
7. Q6: The visible branch requires `action` and `user_id` GET parameters on line 13. Authentication/authorization state remains not visible because the enclosing script/routing context is unavailable. The later `token` check on line 26 occurs after the flagged query at lines 21-22, so it does not protect the flagged sink.
8. Q7: If attacker-controlled nonvalidated input reached line 21, the impact would be SQL injection, potentially database data theft or manipulation. In the visible path, that impact is prevented for `$id` by the digits-only validation on line 14 before query construction and execution.
9. Q8: The weakest link is the manual SQL string construction on line 21 and raw execution on line 22 instead of prepared statements. However, for the specific flagged data path, the defense chain is complete in the provided code because line 14 blocks nonnumeric SQL metacharacters before `$id` is assigned and interpolated.
