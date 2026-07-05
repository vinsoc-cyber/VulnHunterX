# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and directly interpolates cookie-controlled `$id` into a SQL string, which is then executed with `mysqli_query` without any visible escaping or parameterization. The additional context did not reveal any sanitizer, prepared statement, ORM, or other defense that would prevent SQL injection on this path.

## Data flow

source: `$_COOKIE['id']` existence check (line 3) → read into `$id = $_COOKIE['id']` (line 5) → no visible validation/sanitization → manual SQL construction `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"` (line 11) → SQL execution `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13). Additional requested context `global:_DVWA` and `global:___mysqli_ston` was unavailable and adds no visible defense.

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 11: `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";`. This line contains the rule-described construct: a manually constructed SQL string with interpolated variable `$id`. The function is listed as `<unknown>`, so the code appears to be top-level PHP/include code in `vulnerabilities/sqli_blind/source/high.php` rather than a named function.
2. Q1: The dangerous data originates from user-controlled HTTP cookie input. The code checks `isset($_COOKIE['id'])` on line 3 and assigns `$_COOKIE['id']` directly to `$id` on line 5. Cookies are client-controlled input.
3. Q2: Data flow: `$_COOKIE['id']` is checked on line 3, read and assigned to `$id` on line 5, interpolated into the SQL string `$query` on line 11, and the resulting SQL string is executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The additional requested global contexts for `$_DVWA` and `$GLOBALS["___mysqli_ston"]` were unavailable and do not show any additional transformation or defense.
4. Q3: No validation, sanitization, escaping, encoding, type enforcement, allowlist, or prepared statement is visible between the cookie read on line 5 and SQL construction on line 11. Inserting `$id` inside SQL quotes on line 11 is not sufficient because an attacker can include quote characters and SQL syntax in the cookie value.
5. Q4: The sink is `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The dangerous operation is executing a manually constructed SQL query from line 11 that contains untrusted cookie-derived data.
6. Q5: No framework or library automatic protection is visible. `mysqli_query` executes the raw SQL string it receives and does not automatically parameterize interpolated values. The additional context for `global:_DVWA` and `global:___mysqli_ston` was unavailable, so it does not add any visible protection.
7. Q6: Authentication or privilege requirements are not visible in the provided context. The visible triggering condition is that the attacker can supply an `id` cookie so that `isset($_COOKIE['id'])` is true on line 3, and that execution reaches the `MYSQL` branch on lines 8-10.
8. Q7: If an attacker controls `$_COOKIE['id']`, they can inject SQL into the `WHERE user_id = '$id'` clause on line 11. Security impact may include blind SQL injection, unauthorized data extraction, query logic manipulation, and potentially data modification depending on DB permissions and SQL dialect/configuration.
9. Q8: The weakest link is direct interpolation of `$id` from a client-controlled cookie into a SQL statement on line 11, followed by raw execution on line 13. No complete defense is visible in the provided code or in the additional context, which was unavailable.
