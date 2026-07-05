# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context does not change the analysis because it is unavailable and shows no upstream sanitizer or framework protection. The flagged line manually constructs SQL with attacker-controlled `$_GET['username']` at line 12 and executes it via raw `mysqli_query()` at line 13, with no visible escaping, validation, or prepared statement.

## Data flow

HTTP GET source `$_GET['username']` (vulnerabilities/brute/source/low.php:5) → `$user` assignment (line 5) → no visible sanitization/escaping → manual SQL construction `$query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";` (line 12) → SQL execution sink `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13). Secondary path: `$_GET['password']` (line 8) → `$pass` (line 8) → `md5($pass)` (line 9) → interpolated into `$query` (line 12) → `mysqli_query` (line 13). Additional requested contexts for `global:$_GET` and `global:$GLOBALS["___mysqli_ston"]` are unavailable and add no visible sanitization or protection.

## Answers

1. Step 1: The dangerous data originates from HTTP GET user input. Specifically, `$_GET['username']` is read and assigned to `$user` at vulnerabilities/brute/source/low.php:5, and `$_GET['password']` is read and assigned to `$pass` at line 8. The additional context for `global:$_GET` is unavailable, so it does not show any upstream filtering or type guarantee.
2. Step 2: Data flow for username: `$_GET['username']` at vulnerabilities/brute/source/low.php:5 → assigned to `$user` at line 5 → interpolated into the SQL string `$query` at line 12 → passed to `mysqli_query(...)` at line 13. Data flow for password: `$_GET['password']` at line 8 → assigned to `$pass` at line 8 → transformed by `md5($pass)` at line 9 → interpolated into `$query` at line 12 → passed to `mysqli_query(...)` at line 13.
3. Step 3: No validation, sanitization, SQL escaping, or parameter binding is visible for `$user` before it is inserted into SQL at vulnerabilities/brute/source/low.php:12. `$pass` is transformed with `md5()` at line 9, but `md5()` is not a SQL-injection defense such as parameterization or escaping. The newly provided `global:$_GET` and `global:$GLOBALS["___mysqli_ston"]` contexts are unavailable and therefore do not provide any visible defense.
4. Step 4: The sink is `mysqli_query($GLOBALS["___mysqli_ston"],  $query )` at vulnerabilities/brute/source/low.php:13. The unsafe operation is executing a manually constructed SQL string from line 12 that contains attacker-controlled `$user` data inside the `WHERE` clause.
5. Step 5: No framework or library automatic protection is visible. The code uses raw `mysqli_query()` at vulnerabilities/brute/source/low.php:13, not an ORM or prepared statement. No call to `mysqli_prepare()`, bound parameters, or `mysqli_real_escape_string()` is visible. The additional database global context is unavailable and does not show protection.
6. Step 6: The code path is reachable when `isset($_GET['Login'])` is true at vulnerabilities/brute/source/low.php:3. Based only on the visible context, an unauthenticated requester can supply GET parameters `Login`, `username`, and `password`; no authentication, authorization, or admin-only guard is visible.
7. Step 7: If an attacker controls `$user`, they can inject SQL into the authentication query at vulnerabilities/brute/source/low.php:12. Concrete impact includes authentication bypass into the protected area, and potentially data theft or database manipulation depending on the database account’s privileges and DBMS behavior.
8. Step 8: The weakest link is direct interpolation of untrusted `$user` into the SQL query at vulnerabilities/brute/source/low.php:12 without visible SQL escaping or prepared statements before execution at line 13. No complete defense is visible in either the original snippet or the added context.
