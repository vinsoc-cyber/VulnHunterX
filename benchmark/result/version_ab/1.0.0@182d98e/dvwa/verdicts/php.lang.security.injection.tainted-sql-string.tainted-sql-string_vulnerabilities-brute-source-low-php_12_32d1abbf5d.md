# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 12 is a manually constructed SQL query containing direct interpolation of `$user`, which comes from `$_GET['username']` on line 5, and the query is executed by raw `mysqli_query` on line 13. No visible validation, escaping, prepared statement, ORM protection, or upstream defense is present in the original snippet or the unavailable additional context.

## Data flow

HTTP GET source `$_GET['username']` at `vulnerabilities/brute/source/low.php:5` → assigned to `$user` on line 5 → directly interpolated into SQL string `$query` on flagged line 12 → executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. Secondary flow: `$_GET['password']` on line 8 → `$pass` on line 8 → `md5($pass)` on line 9 → interpolated into `$query` on line 12 → executed on line 13. Additional requested caller/global context was unavailable and adds no visible sanitization or protection.

## Answers

1. Step 0 / flagged line: The flagged line is present at line 12 and exactly reads: `$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`. The construct described by the rule is present on that line: a manually constructed SQL string interpolating variables directly into SQL. It lives in top-level PHP code in `vulnerabilities/brute/source/low.php`; no named function is shown, and the function is listed as `<unknown>`.
2. Step 1: The potentially dangerous data originates from HTTP GET parameters, which are user-controlled input: `$_GET['username']` is assigned to `$user` on line 5, and `$_GET['password']` is assigned to `$pass` on line 8. The added caller context is unavailable and does not show any upstream validation.
3. Step 2: Data flow with all visible assignments and transformations: line 3 checks `isset($_GET['Login'])`; line 5 assigns `$_GET['username']` to `$user`; line 8 assigns `$_GET['password']` to `$pass`; line 9 transforms `$pass` via `md5($pass)`; line 12 interpolates `$user` and `$pass` into `$query`; line 13 executes `$query` using `mysqli_query(...)`.
4. Step 3: No SQL-specific validation, sanitization, escaping, or encoding is visible. `$user` receives no transformation before being placed into SQL on line 12. `$pass` is hashed with `md5()` on line 9, but MD5 is not SQL escaping or parameterization and does not protect the `$user` injection point. The additional requested global/caller context was unavailable, so it provides no visible defense.
5. Step 4: The sink is the SQL query construction on flagged line 12, followed by execution at line 13 via `mysqli_query($GLOBALS["___mysqli_ston"], $query)`. The unsafe operation is directly interpolating user-controlled input into a SQL string and executing it without prepared statements or escaping.
6. Step 5: No automatic framework or library protection is visible. The code uses raw `mysqli_query` on line 13, not an ORM or prepared statement. The requested global database connection context for `$GLOBALS["___mysqli_ston"]` is unavailable and shows no automatic parameterization or escaping.
7. Step 6: Based on the visible code, an attacker appears to need no prior authentication; the code path is entered when `$_GET['Login']` is set on line 3. No authentication, authorization, CSRF, or role check is visible before the query.
8. Step 7: The concrete security impact is SQL injection through `$user` on line 12, potentially allowing authentication bypass, unauthorized data access, or database manipulation depending on database permissions and configuration.
9. Step 8: The weakest link is direct interpolation of untrusted GET input `$user` into the SQL string on line 12, followed by execution on line 13, with no visible prepared statement, escaping, whitelist validation, or ORM protection. No complete defense is visible in the provided or additional context.
10. Re-examination with additional context: The new context is unavailable for both the top-level caller/include and `$GLOBALS["___mysqli_ston"]`, so it does not change the prior analysis. It neither shows an upstream sanitizer nor a safe database abstraction that would neutralize the SQL injection risk.
