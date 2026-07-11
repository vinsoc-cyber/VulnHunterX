# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not reveal any upstream or framework defense. The visible code clearly takes attacker-controlled cookie data from line 5, embeds it unsanitized into a manually constructed SQL query on the flagged line 11, and executes it with `mysqli_query` on line 13.

## Data flow

HTTP cookie source `$_COOKIE['id']` checked for existence (vulnerabilities/sqli_blind/source/high.php:3) → assigned directly to `$id` (line 5) → DB branch selected via `$_DVWA['SQLI_DB']` (line 8; global context unavailable) → MySQL case (line 9) → `$id` interpolated into `$query` on flagged line 11 → complete SQL string executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13; connection global context unavailable)

## Answers

1. Step 0 / flagged line location: The flagged line 11 is present and is exactly `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";`. The construct described by the rule is present on that line: a manually constructed SQL string interpolating `$id`. The enclosing function is still shown as `<unknown>` / top-level snippet context; no named function is visible.
2. Step 1 / source: The potentially dangerous data originates from user-controlled HTTP cookie input. Line 3 checks `isset($_COOKIE['id'])`, and line 5 assigns `$_COOKIE['id']` directly to `$id`. The new global context for `$_DVWA`, `$GLOBALS["___mysqli_ston"]`, and `$sqlite_db_connection` is unavailable and does not change this source analysis.
3. Step 2 / trace: In `vulnerabilities/sqli_blind/source/high.php`, `$_COOKIE['id']` is checked for existence on line 3, assigned directly to `$id` on line 5, the database type branch is selected via `$_DVWA['SQLI_DB']` on line 8, the MySQL branch begins at line 9, `$id` is interpolated into `$query` on the flagged line 11, and `$query` is passed to `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The sibling SQLite path also constructs a query using `$id` on line 33 and executes it on line 35, but the reported flagged sink is line 11.
4. Step 3 / validation/sanitization: No validation, sanitization, escaping, type casting, allowlist, or prepared-statement binding is visible between the cookie read on line 5 and the SQL construction on line 11. The `isset` check on line 3 only confirms presence and does not constrain SQL metacharacters. The additional global contexts are unavailable, so they provide no visible defense.
5. Step 4 / sink: The flagged sink is the SQL string construction on line 11, where user-controlled `$id` is placed inside a quoted SQL literal. The query is then executed by `mysqli_query` on line 13. The dangerous operation is executing a manually constructed SQL query containing unsanitized user input.
6. Step 5 / framework/library protections: No framework or library protection is visible. `mysqli_query` on line 13 executes a complete SQL string; it does not parameterize or escape interpolated values automatically. No ORM or prepared statement is used in the provided code. The requested global connection/configuration context is unavailable and therefore does not show any automatic protection.
7. Step 6 / privilege/authentication: No authentication, authorization, or admin-only guard is visible in the provided context. The only visible requirement to reach the vulnerable block is that the attacker supplies an `id` cookie so that line 3 evaluates true. Any caller/routing authentication context remains unavailable.
8. Step 7 / security impact: If an attacker controls `$_COOKIE['id']`, they can alter the SQL query on line 11. This can enable SQL injection, including blind SQL injection because the response reveals whether a row exists through different behavior/messages on lines 45-59. Depending on database privileges, impact can include unauthorized data disclosure or database manipulation.
9. Step 8 / weakest link: The single weakest link is direct interpolation of untrusted cookie data into a SQL statement at line 11, followed by execution at line 13. No complete defense is visible: there is no local validation, escaping, type enforcement, or parameterized query on the flagged path.
