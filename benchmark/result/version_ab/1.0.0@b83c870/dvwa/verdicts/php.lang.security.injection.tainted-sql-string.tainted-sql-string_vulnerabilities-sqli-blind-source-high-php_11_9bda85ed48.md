# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the visible tainted flow: client-controlled cookie data reaches a manually constructed SQL string at the flagged line and is executed by `mysqli_query` without any visible validation, escaping, or prepared statement. The path is visibly reachable when the `id` cookie is set and the MYSQL branch is selected, so this is a clear SQL injection finding.

## Data flow

source `$_COOKIE['id']` (vulnerabilities/sqli_blind/source/high.php:5) → assignment `$id = $_COOKIE['id']` (line 5) → raw SQL interpolation into `$query` (line 11) → execution via `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13). Additional requested globals `$_DVWA`, `$GLOBALS["___mysqli_ston"]`, and `$html` were unavailable and introduce no visible sanitization or protection.

## Answers

1. Step 0 / located flagged line: vulnerabilities/sqli_blind/source/high.php:11 is exactly `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";`. The rule-described construct is present on that line: a manually constructed SQL string interpolates `$id` directly into the query. The code appears in function `<unknown>` / file-scope snippet; no named enclosing function is visible.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP cookie input. `$_COOKIE['id']` is checked at line 3 and read at line 5. Cookies are client-controlled request data.
3. Step 2: Data flow is: `$_COOKIE['id']` source at line 5 → assigned directly to `$id` at line 5 → `$id` interpolated into SQL string `$query` at line 11 → `$query` passed to `mysqli_query($GLOBALS["___mysqli_ston"], $query)` at line 13. The additional requested global context for `$_DVWA`, `$GLOBALS["___mysqli_ston"]`, and `$html` is unavailable and does not add any visible transformation or protection.
4. Step 3: No validation, sanitization, escaping, encoding, type casting, allowlist check, or prepared-statement binding is visible between the cookie read at line 5 and SQL construction at line 11. The unavailable global context does not reveal any defense. There is no visible use of `mysqli_real_escape_string`, `(int)$id`, parameterized queries, or an ORM.
5. Step 4: The sink is SQL execution at line 13: `mysqli_query($GLOBALS["___mysqli_ston"],  $query )`. The dangerous operation is executing a raw SQL string built on line 11 with untrusted `$id` embedded inside single quotes.
6. Step 5: No framework or library automatic protection is visible. `mysqli_query` executes the provided SQL string and does not automatically parameterize or escape interpolated variables. The additional context for the database connection is unavailable, but no visible framework-level protection or ORM is present on this path.
7. Step 6: Authentication or privilege requirements are not visible in the provided context. The visible gates are only `isset($_COOKIE['id'])` at line 3 and the `MYSQL` switch case selected through `$_DVWA['SQLI_DB']` at lines 8-10. Any attacker who can reach this code path and set the `id` cookie can control `$id`; whether reaching the page requires authentication is not shown.
8. Step 7: If an attacker controls `$id`, they can inject SQL into `WHERE user_id = '$id'` at line 11. Concrete impact can include unauthorized data access or manipulation depending on database permissions. Because the response only reveals whether a row exists on lines 45-59, this is consistent with blind SQL injection and can still support data extraction via boolean or timing behavior.
9. Step 8: The weakest link is direct interpolation of client-controlled cookie data into a SQL query on line 11, followed by execution on line 13, with no visible SQL-specific escaping, validation, or parameterization. No complete defense is visible in the provided or additional context.
