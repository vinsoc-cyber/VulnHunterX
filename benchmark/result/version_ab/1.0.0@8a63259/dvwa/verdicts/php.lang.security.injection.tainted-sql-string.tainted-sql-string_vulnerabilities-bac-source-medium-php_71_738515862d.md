# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/medium.php:71

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the analysis: the visible code clearly assigns request-derived data to `$ip` on line 69 and interpolates it into a manually constructed SQL string on lines 71-72 before executing it with raw `mysqli_query` on line 73. No adequate SQL sanitization, escaping, prepared statement, or framework protection is visible on this path.

## Data flow

source: `$_SERVER['HTTP_X_FORWARDED_FOR']` / `$_SERVER['REMOTE_ADDR']` (line 69) → assignment: `$ip` (line 69) → no visible sanitization/escaping → SQL construction: `$log_query = "INSERT INTO bac_log ... '{$ip}'"` (lines 71-72) → sink: `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` (line 73)

## Answers

1. Step 0 / flagged line: line 71 is exactly `$log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES `. The rule's construct is present on that line: it begins a manually constructed SQL string, with variable interpolation continuing on line 72.
2. Step 1: The dangerous data originates from HTTP request/server input on line 69: `$ip = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];`. `$_SERVER['HTTP_X_FORWARDED_FOR']` is client-controllable in typical deployments. `$id` and `$current_user_id` may also be relevant, but their ultimate sources remain not visible in the provided context.
3. Step 2: The visible data flow is: `$_SERVER['HTTP_X_FORWARDED_FOR']` or `$_SERVER['REMOTE_ADDR']` on line 69 → assigned to `$ip` on line 69 → interpolated into `$log_query` on lines 71-72 → executed by `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` on line 73. Separately, `$id` is used in SQL on lines 21 and 28, `$target_id = $user_exists ? $id : 0` on line 70, and `$target_id` is interpolated into the same SQL query on line 72.
4. Step 3: No SQL-specific validation, sanitization, escaping, casting, or parameter binding is visible for `$ip` between its assignment on line 69 and its SQL interpolation on line 72. No call to `mysqli_real_escape_string`, prepared statements, integer casting, allowlist validation, or ORM protection is visible. The comment on line 68 says 'only log numeric target_id', but line 70 does not validate or cast `$id`; it only chooses `$id` or `0`.
5. Step 4: The sink is `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` on line 73. The dangerous operation is executing a manually constructed SQL string built on lines 71-72 with unescaped variable interpolation, especially ` '{$ip}' ` on line 72.
6. Step 5: No framework or library automatic protection is visible. The code uses raw `mysqli_query` on lines 22, 29, 53, 65, and 73. There is no visible prepared statement, ORM, query builder, or automatic SQL parameterization. The additional requested context for `global:___mysqli_ston` was unavailable, so it does not change this assessment.
7. Step 6: The exact outer authentication state is not visible because the enclosing function and caller context remain unavailable. However, within the provided code, the logging block on lines 49-73 appears to run regardless of whether the token check on line 26 succeeds, because it follows the `if/else` block ending at line 47. The visible token check is only `$_GET['token'] == 'user_token'` on line 26 and is not a SQL-injection defense.
8. Step 7: If an attacker controls `$ip`, they can inject SQL into the `INSERT INTO bac_log` statement on lines 71-73. The concrete impact is SQL injection, potentially allowing unauthorized database modification or data access depending on MySQL permissions and query execution configuration.
9. Step 8: The weakest link is direct interpolation of request-derived `$ip` from line 69 into the SQL string on lines 71-72, followed by raw execution with `mysqli_query` on line 73. No visible defense completes the chain; the additional context provided was unavailable and does not add any sanitizer or guard.
