# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The visible code shows a complete exploitable SQL injection path: user-controlled cookie data from line 5 is directly embedded into a SQL string on line 11 and executed on line 13. No prepared statement, escaping, validation, or other visible defense is present, and the additional context did not change the analysis.

## Data flow

HTTP cookie source `$_COOKIE['id']` checked for presence only (line 3) → assigned directly to `$id` (line 5) → `$id` interpolated into manually constructed SQL string `$query` (flagged line 11) → `$query` executed by `mysqli_query($GLOBALS["___mysqli_ston"], $query)` (line 13). Additional requested global context for `$_DVWA` and `$GLOBALS["___mysqli_ston"]` was unavailable and adds no visible sanitization or parameterization.

## Answers

1. Step 0 / Flagged line: The flagged line is present at line 11 and is exactly `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";`. This line contains the rule-described construct: a manually constructed SQL string with interpolated variable `$id`.
2. Step 1 / Source: The dangerous data originates from user-controlled HTTP cookie input. The code checks `isset($_COOKIE['id'])` on line 3 and assigns `$_COOKIE['id']` directly to `$id` on line 5.
3. Step 2 / Data trace: In the MySQL branch, `$_COOKIE['id']` on line 5 flows unchanged into `$id`, then `$id` is interpolated into `$query` on flagged line 11, then `$query` is passed to `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. In the SQLite branch, the same `$id` flows into `$query` on line 33 and is executed via `$sqlite_db_connection->query($query)` on line 35, although the specific finding is for line 11.
4. Step 3 / Validation, sanitization, or encoding: No validation, sanitization, escaping, type casting, allowlisting, or parameter binding is visible between the source on line 5 and SQL construction on line 11. The presence check on line 3 only confirms the cookie exists; it does not constrain content. Wrapping `$id` in SQL quotes on line 11 is not sufficient because attacker-controlled quote characters can break out of the string.
5. Step 4 / Sink: The sink for the flagged path is `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13. The dangerous operation is execution of a manually constructed SQL query containing untrusted cookie data. The query construction itself occurs at line 11.
6. Step 5 / Framework or library protections: No automatic framework or library protection is visible. The code uses raw `mysqli_query` on line 13 rather than a prepared statement or ORM. The requested additional global context for `$_DVWA` and `$GLOBALS["___mysqli_ston"]` was unavailable and does not add any visible defense.
7. Step 6 / Privilege or authentication needed: Not visible in provided context. The only visible trigger condition is that the attacker can send or set the `id` cookie, checked on line 3. No authentication, authorization, or role check is shown.
8. Step 7 / Security impact: If an attacker controls `$_COOKIE['id']`, they can inject SQL into the `WHERE user_id = '$id'` clause on line 11 before execution on line 13. Impact can include unauthorized data disclosure or manipulation depending on database privileges; the boolean-style response behavior on lines 45-59 can also support blind SQL injection inference.
9. Step 8 / Weakest link: The weakest link is direct interpolation of `$id` from `$_COOKIE['id']` into the SQL string on line 11 with no visible validation, escaping, or prepared statement before execution on line 13. The additional requested context was unavailable and did not reveal any defense that would make the path safe.
