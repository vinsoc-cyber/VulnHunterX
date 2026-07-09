# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 12 is clearly a manually constructed SQL query containing unsanitized user-controlled `$user` from `$_GET['username']`, and that query is executed directly by `mysqli_query` on line 13. The additional context was unavailable and does not show any upstream validation, escaping, prepared statement use, or other defense that would prevent SQL injection on this path.

## Data flow

source `$_GET['username']` (vulnerabilities/brute/source/low.php:5) → `$user` with no sanitization (line 5) → interpolated into manually constructed SQL string `$query` (line 12) → executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13). Secondary flow: `$_GET['password']` (line 8) → `$pass` (line 8) → `md5($pass)` (line 9, not SQL sanitization) → interpolated into `$query` (line 12) → `mysqli_query` (line 13). Additional requested contexts for `global:$GLOBALS["___mysqli_ston"]` and `function:<unknown>` were unavailable and add no visible defense or transformation.

## Answers

1. Step 1: The potentially dangerous data originates from HTTP GET parameters in the provided code: `$_GET['username']` is assigned to `$user` on line 5, and `$_GET['password']` is assigned to `$pass` on line 8. The added context for `global:$GLOBALS["___mysqli_ston"]` and `function:<unknown>` is unavailable and does not change this source analysis.
2. Step 2: Data flow is: `$_GET['username']` on line 5 → `$user` on line 5 → interpolated directly into the SQL string `$query` on line 12. Separately, `$_GET['password']` on line 8 → `$pass` on line 8 → `md5($pass)` on line 9 → `$pass` on line 9 → interpolated into `$query` on line 12. Then `$query` is executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The additional requested contexts were unavailable, so there are no additional transformations or defenses to add.
3. Step 3: No validation, SQL escaping, prepared-statement binding, allowlist, or other SQL-specific sanitization is visible. `md5($pass)` on line 9 is a hash transformation, not SQL sanitization or parameterization. `$user` from line 5 is not sanitized before interpolation on line 12. The unavailable additional context provides no visible defense.
4. Step 4: Step 0 / flagged line location: the exact flagged line is line 12: `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`. The code is in function `<unknown>` / apparent top-level PHP code in `vulnerabilities/brute/source/low.php`. The construct described by the rule is present on that line: a manually constructed SQL string containing user-derived variables. The execution sink is line 13, `mysqli_query($GLOBALS["___mysqli_ston"],  $query )`, which executes the attacker-influenced SQL string.
5. Step 5: No framework or library automatic protection is visible. The code uses raw `mysqli_query` on line 13 rather than a prepared statement, parameterized query, or ORM. The requested global DB connection context is unavailable and does not reveal any protection.
6. Step 6: Based only on the visible code, an unauthenticated attacker can trigger the path by supplying GET parameter `Login` to satisfy line 3 and controlling `username`/`password` parameters used on lines 5 and 8. No authentication, authorization, or privilege check is visible before the SQL query.
7. Step 7: If an attacker controls `$user`, they can inject SQL into the WHERE clause on line 12 before execution on line 13. Concrete impacts include authentication bypass and unauthorized access to user data; depending on database permissions and configuration, SQL injection may also allow broader data disclosure or manipulation.
8. Step 8: The single weakest link is the direct interpolation of unsanitized `$_GET['username']` into the SQL string on line 12, followed by execution via raw `mysqli_query` on line 13. No complete defense is visible in the provided or additional context.
