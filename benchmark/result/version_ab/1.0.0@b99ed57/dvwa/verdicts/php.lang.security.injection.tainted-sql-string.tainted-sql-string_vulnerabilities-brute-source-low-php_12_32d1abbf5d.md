# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 12 is a manually constructed SQL string containing `$user`, which comes directly from `$_GET['username']` on line 5 and is executed by `mysqli_query` on line 13. No prepared statement, SQL escaping, validation, or framework protection is visible, and the additional requested global context was unavailable and does not reveal any defense.

## Data flow

vulnerabilities/brute/source/low.php:3 `isset($_GET['Login'])` gates execution → vulnerabilities/brute/source/low.php:5 `$_GET['username']` assigned to `$user` → vulnerabilities/brute/source/low.php:12 `$user` interpolated into `$query` SQL string → vulnerabilities/brute/source/low.php:13 `$query` executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)`. Parallel flow: vulnerabilities/brute/source/low.php:8 `$_GET['password']` assigned to `$pass` → vulnerabilities/brute/source/low.php:9 `$pass = md5($pass)` → vulnerabilities/brute/source/low.php:12 `$pass` interpolated into `$query` → vulnerabilities/brute/source/low.php:13 executed. Additional context for `global:$GLOBALS["___mysqli_ston"]` was unavailable and adds no visible sanitizer or protection.

## Answers

1. Step 0 / flagged line: The flagged line is present at line 12 and reads exactly: `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`. This is in function `<unknown>`; from the provided code it appears to be top-level PHP code. The construct described by the rule is present: a manually constructed SQL string containing interpolated variables.
2. Step 1: The dangerous data originates from HTTP GET parameters. `$user` is assigned from `$_GET['username']` on line 5, and `$pass` is assigned from `$_GET['password']` on line 8. These are user-controlled request inputs. The additional context for `global:$GLOBALS["___mysqli_ston"]` is unavailable and does not change this source analysis.
3. Step 2: Data flow: execution enters the block if `isset($_GET['Login'])` is true on line 3. `$_GET['username']` flows into `$user` on line 5, then directly into the SQL string on line 12. `$_GET['password']` flows into `$pass` on line 8, is transformed by `md5($pass)` on line 9, then flows into the SQL string on line 12. `$query` is executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13.
4. Step 3: No sufficient validation, sanitization, or SQL encoding is visible. There is no validation, allowlist, escaping, or parameter binding for `$user` before it is interpolated into SQL on line 12. `$pass` is hashed with `md5()` on line 9, but hashing is not SQL parameterization; in any case, the username remains directly injectable. The additional global database context is unavailable and shows no defense.
5. Step 4: The sink is the SQL query construction on line 12 followed by execution through `mysqli_query(...)` on line 13. The unsafe operation is interpolating attacker-controlled data into a SQL string and executing it without prepared statements or escaping.
6. Step 5: No automatic framework or library protection is visible. The code uses raw `mysqli_query` on line 13. The requested `global:$GLOBALS["___mysqli_ston"]` context was unavailable, and there is no visible ORM, prepared statement wrapper, or automatic parameterization at this sink.
7. Step 6: Based on the visible code, an attacker needs only to send a request with `Login` set in `$_GET` to enter the block at line 3. No prior authentication, authorization, or admin-only guard is visible.
8. Step 7: Concrete impact includes SQL injection against the login query. An attacker controlling `$_GET['username']` can potentially alter the `WHERE` clause to bypass authentication, access user records, or manipulate database behavior depending on database privileges and mysqli/database configuration.
9. Step 8: The weakest link is direct interpolation of `$user` from `$_GET['username']` into the SQL string at line 12, followed by raw execution at line 13, with no visible escaping or parameterization. No complete defense is visible in the provided code or the additional unavailable context.
