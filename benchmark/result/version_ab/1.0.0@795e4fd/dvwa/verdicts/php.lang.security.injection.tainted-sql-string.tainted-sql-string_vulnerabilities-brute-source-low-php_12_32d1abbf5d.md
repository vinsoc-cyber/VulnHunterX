# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged SQL string on line 12 directly includes user-controlled `$user` from `$_GET['username']` without any visible SQL-specific sanitization or parameterization, and the constructed query is executed with `mysqli_query` on line 13. The additional context was unavailable and does not alter the visible exploitable source-to-sink path.

## Data flow

`$_GET['username']` (line 5) → `$user` assignment (line 5) → direct interpolation into `$query` (line 12) → execution by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13). Password path: `$_GET['password']` (line 8) → `$pass` (line 8) → `md5($pass)` (line 9) → interpolation into `$query` (line 12) → `mysqli_query` (line 13). Additional context `global:___mysqli_ston` was unavailable and adds no visible sanitizer or prepared-statement protection.

## Answers

1. Step 0 / located flagged line: Line 12 is exactly `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`. The rule's construct is present on that line: a manually constructed SQL string embeds variables directly inside SQL.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP GET parameters. `$user` is assigned from `$_GET['username']` on line 5, and `$pass` is assigned from `$_GET['password']` on line 8. The only visible gate is `isset($_GET['Login'])` on line 3.
3. Step 2: Username flow: `$_GET['username']` line 5 → `$user` line 5 → interpolated into `$query` line 12 → passed to `mysqli_query` line 13. Password flow: `$_GET['password']` line 8 → `$pass` line 8 → transformed by `md5($pass)` line 9 → interpolated into `$query` line 12 → passed to `mysqli_query` line 13. Additional context for `global:___mysqli_ston` was unavailable and does not show any additional sanitization or parameterization.
4. Step 3: No validation, sanitization, SQL escaping, allowlist, or parameter binding is visible for `$user` before it reaches the SQL string on line 12. `$pass` is transformed with `md5()` on line 9, but that is not SQL escaping or prepared-statement parameterization, and it does not protect the `$user` value.
5. Step 4: The sink is `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The unsafe operation is execution of a manually constructed SQL query string from line 12 containing untrusted `$user` data.
6. Step 5: No automatic framework or library protection is visible. The code uses raw `mysqli_query` on line 13, not an ORM or prepared statement. The additional requested global context for `$GLOBALS["___mysqli_ston"]` was unavailable and does not provide evidence of automatic parameterization.
7. Step 6: Based on the provided code, the attacker appears to need only unauthenticated HTTP GET access with a `Login` parameter to enter the block at line 3 and control `username` and `password` on lines 5 and 8. No authentication or admin-only guard is visible.
8. Step 7: Concrete impact: SQL injection through `$user` can alter the WHERE clause on line 12, potentially allowing authentication bypass, unauthorized access to user data, and database data theft or manipulation depending on database privileges.
9. Step 8: The weakest link is direct interpolation of untrusted `$user` from line 5 into the SQL query on line 12, followed by raw execution on line 13. No complete defense is visible because there is no prepared statement, escaping, or validation on the username path.
