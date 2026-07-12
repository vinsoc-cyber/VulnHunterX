# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible and contains a manually constructed SQL query using `$user`, which comes directly from `$_GET['username']` on line 5. Because this attacker-controlled value reaches `mysqli_query` on line 13 without visible sanitization, escaping, or parameter binding, this is a clear SQL injection vulnerability.

## Data flow

vulnerabilities/brute/source/low.php:5 `$_GET['username']` → vulnerabilities/brute/source/low.php:5 `$user` → vulnerabilities/brute/source/low.php:12 interpolated into `$query` → vulnerabilities/brute/source/low.php:13 executed by `mysqli_query`; secondary path: vulnerabilities/brute/source/low.php:8 `$_GET['password']` → vulnerabilities/brute/source/low.php:9 `md5($pass)` → vulnerabilities/brute/source/low.php:12 `$query` → vulnerabilities/brute/source/low.php:13 `mysqli_query`

## Answers

1. Step 0 / Flagged line located: line 12 is exactly `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`. The construct described by the rule is present on that line: a manually constructed SQL string containing interpolated variables. The enclosing function is shown as `<unknown>` in the provided context; the code appears to be top-level PHP guarded by `if( isset( $_GET[ 'Login' ] ) )` on line 3.
2. Step 1 / Vulnerability class: The rule is `php.lang.security.injection.tainted-sql-string.tainted-sql-string`, CWE-89 SQL Injection. The flagged sink is a SQL query string built from user-controlled input and executed via MySQLi.
3. Step 2 / Source: The dangerous data originates from HTTP GET parameters. `$user` is assigned from `$_GET['username']` on line 5, and `$pass` is assigned from `$_GET['password']` on line 8. These are remote attacker-controllable inputs. The code path is entered when `$_GET['Login']` is set on line 3.
4. Step 3 / Trace: `$_GET['username']` at line 5 → `$user` at line 5 → interpolated into `$query` on line 12 → `$query` passed to `mysqli_query(...)` on line 13. Separately, `$_GET['password']` at line 8 → `$pass` at line 8 → transformed by `md5($pass)` on line 9 → interpolated into `$query` on line 12 → `$query` passed to `mysqli_query(...)` on line 13.
5. Step 4 / Validation, sanitization, or encoding: No SQL validation, escaping, or parameterization is visible for `$user`. The password is hashed with `md5()` on line 9, but that is not SQL escaping or a prepared-statement defense. No `mysqli_real_escape_string`, bound parameter, allowlist check, or ORM is visible before line 12.
6. Step 5 / Sink: The sink is the construction of the SQL string at line 12 and its execution by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The dangerous operation is executing a query whose SQL syntax includes attacker-controlled `$user` inside quoted SQL text.
7. Step 6 / Framework or library protections: No automatic protection is visible. The code uses raw `mysqli_query` on line 13 with a manually interpolated SQL string from line 12, not a prepared statement or ORM.
8. Step 7 / Required attacker privilege: Based only on the provided code, this appears reachable by an unauthenticated remote attacker who can provide GET parameters `Login`, `username`, and `password`; no authentication or authorization guard is visible before line 3 or line 12.
9. Step 8 / Concrete impact: An attacker controlling `username` can inject SQL into the `WHERE user = '$user'` predicate on line 12. Potential impacts include authentication bypass and unauthorized database access or manipulation, depending on database privileges.
10. Step 9 / Weakest link: The weakest link is direct interpolation of `$_GET['username']` into the SQL query on line 12, followed by execution on line 13, with no visible prepared statement, escaping, or allowlist validation.
