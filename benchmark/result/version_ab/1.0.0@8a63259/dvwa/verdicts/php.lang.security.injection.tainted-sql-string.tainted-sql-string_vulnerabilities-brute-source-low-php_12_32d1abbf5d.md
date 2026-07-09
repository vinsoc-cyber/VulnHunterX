# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and clearly constructs SQL using user-controlled GET input, especially `$user`, without visible SQL sanitization or parameterization. The query is then executed by raw `mysqli_query` on line 13, creating a concrete SQL injection path.

## Data flow

vulnerabilities/brute/source/low.php:3 checks isset($_GET['Login']) → vulnerabilities/brute/source/low.php:5 assigns $_GET['username'] to $user → vulnerabilities/brute/source/low.php:12 interpolates $user into $query → vulnerabilities/brute/source/low.php:13 executes $query via mysqli_query($GLOBALS["___mysqli_ston"], $query). Secondary flow: vulnerabilities/brute/source/low.php:8 assigns $_GET['password'] to $pass → vulnerabilities/brute/source/low.php:9 md5($pass) → vulnerabilities/brute/source/low.php:12 interpolates $pass into $query → vulnerabilities/brute/source/low.php:13 executes it. Additional context for global:___mysqli_ston was unavailable and adds no visible defense.

## Answers

1. Step 0 / flagged line: The flagged line is line 12: `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`. This line contains the construct described by the rule: a manually constructed SQL string with interpolated variables.
2. Function/location: The code context labels the function as `<unknown>`. In the provided snippet, the flagged line appears to live in top-level PHP code in `vulnerabilities/brute/source/low.php`, not inside a named function.
3. Effect of additional context: The requested `global:___mysqli_ston` context is unavailable out-of-snippet, so it does not change the prior analysis. The visible sink still calls `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13 with a manually constructed query from line 12.
4. Step 1: The potentially dangerous data originates from HTTP GET parameters, which are user-controlled input: `$_GET['username']` assigned on line 5 and `$_GET['password']` assigned on line 8. The code path is entered when `$_GET['Login']` is set on line 3.
5. Step 2: Data trace: `$_GET['username']` flows to `$user` on line 5, then into the SQL string `$query` on line 12. `$_GET['password']` flows to `$pass` on line 8, then through `md5($pass)` on line 9, then into `$query` on line 12. `$query` is passed to `mysqli_query(...)` on line 13.
6. Step 3: No SQL-specific validation, sanitization, escaping, or encoding is visible. `md5($pass)` on line 9 transforms the password value, but it is not a SQL injection defense and does not sanitize `$user` at all. No `mysqli_real_escape_string`, prepared statement, parameter binding, allowlist validation, or ORM protection is visible.
7. Step 4: The sink is `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The dangerous operation is executing a manually constructed SQL query containing attacker-controlled `$user` from line 5.
8. Step 5: No framework or library automatic SQL injection protection is visible. The code uses raw `mysqli_query` on line 13, and the unavailable `global:___mysqli_ston` context provides no evidence of automatic parameterization or escaping.
9. Step 6: Based on the visible code, an attacker only needs unauthenticated access capable of sending GET parameters, because the only guard shown is `isset($_GET['Login'])` on line 3. No authentication, role check, CSRF requirement, or admin-only guard is visible.
10. Step 7: The concrete security impact is SQL injection. In this login query, an attacker controlling `$user` can potentially bypass authentication, read user data, or manipulate database results. Broader data theft or database manipulation depends on database privileges, which are not visible.
11. Step 8: The weakest link is direct interpolation of untrusted `$user` into the SQL string on line 12, followed by execution through `mysqli_query` on line 13, with no visible prepared statement, escaping, or validation.
