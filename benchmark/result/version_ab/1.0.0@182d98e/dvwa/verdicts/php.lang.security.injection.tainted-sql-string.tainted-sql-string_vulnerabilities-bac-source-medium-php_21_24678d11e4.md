# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/medium.php:21

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged SQL construction is present at line 21 and is executed at line 22, but the only visible flow into `$id` comes from `$_GET['user_id']` after the strict digit-only allowlist at line 14. Because this validation prevents SQL metacharacters from reaching the quoted SQL context, the flagged sink is not exploitable as SQL injection in the provided code.

## Data flow

source `$_GET['user_id']` (`vulnerabilities/bac/source/medium.php`:13-14) → validation `preg_match('/^\d+$/', $_GET['user_id'])` (line 14) → assignment `$id = $_GET['user_id']` (line 17) → SQL string construction `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'";` (line 21) → SQL execution `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` (line 22). Additional requested context for `global:___mysqli_ston` and enclosing/auth wrappers was unavailable and adds no new visible flow.

## Answers

1. Step 0 / Flagged line located: The flagged line is line 21: `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'";`. The construct described by the rule is present: a manually constructed SQL string interpolating `$id`. It lives in `Function: <unknown>`; the provided snippet appears to be top-level PHP script code, but no named enclosing function/controller is visible.
2. Step 1 / Source: The potentially dangerous data originates from user-controlled HTTP GET input: `$_GET['user_id']`, checked at lines 13-14. `$_GET['action']` is also required for reachability at line 13, but the value interpolated into the flagged SQL string comes from `$_GET['user_id']`.
3. Step 2 / Trace: `$_GET['user_id']` is checked for presence at line 13 → validated by `preg_match('/^\d+$/', $_GET['user_id'])` at line 14 → if validation passes, assigned to `$id` at line 17 → interpolated into `$check_query` at line 21 → executed by `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` at line 22.
4. Step 3 / Validation/Sanitization: Yes. Line 14 applies a strict allowlist regex, `/^\d+$/`, requiring the entire `user_id` value to consist only of one or more digits. For SQL injection at line 21, this is sufficient because the value cannot contain quotes, whitespace, SQL operators, comments, or statement terminators needed to escape the quoted string context. The additional requested context for `global:___mysqli_ston` and enclosing/auth wrapper was unavailable and does not change the visible validation.
5. Step 4 / Sink: The sink is the SQL query constructed at line 21 and executed at line 22 with `mysqli_query`. The risky operation is executing a manually constructed SQL string containing user-influenced data. However, the data reaching this sink is constrained to digits by line 14.
6. Step 5 / Framework/Library Protections: No automatic framework or ORM protection is visible. The code uses raw `mysqli_query` at line 22 rather than prepared statements. The relevant visible protection is the explicit digit-only validation at line 14, not any framework/library parameterization. The requested `global:___mysqli_ston` context was unavailable.
7. Step 6 / Required Privilege/Auth State: Not visible in provided context. The local code path requires `$_GET['action']` and `$_GET['user_id']` to be set at line 13 and for `user_id` to pass the numeric regex at line 14. The token check at line 26 occurs after the flagged query at lines 21-22 and therefore does not protect this sink. Outer authentication/authorization context remains unavailable.
8. Step 7 / Security Impact: If SQL injection were possible at line 21, impact could include database data theft or manipulation. In the provided code path, exploitation is not demonstrated because attacker input is restricted to digits before reaching the SQL execution at line 22.
9. Step 8 / Weakest Link: The weakest link is manual SQL construction and raw `mysqli_query` use at lines 21-22 instead of prepared statements. For this specific flagged sink, however, the defense chain includes a complete visible allowlist at line 14 that prevents SQL injection characters from reaching `$id`.
