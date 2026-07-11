# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line 11 is present in function `<unknown>` and manually constructs SQL with `$id` from the client-controlled cookie assigned on line 5. The value reaches `mysqli_query` on line 13 with no visible sanitization, escaping, validation, or parameterization, and the added context did not reveal any defense.

## Data flow

source `$_COOKIE['id']` in vulnerabilities/sqli_blind/source/high.php:3-5 → assigned directly to `$id` at line 5 → database branch selected using `$_DVWA['SQLI_DB']` at line 8, with global definition unavailable → MYSQL branch flagged sink at line 11 constructs `$query` using `$id` → raw execution at line 13 via `mysqli_query($GLOBALS["___mysqli_ston"], $query)`, with connection global definition unavailable

## Answers

1. Step 1 / Source: The dangerous data originates from user-controlled cookie input: `$_COOKIE['id']` is checked for presence on line 3 and assigned to `$id` on line 5. Cookies are client-controlled. The additional requested global contexts for `$_DVWA`, `$GLOBALS["___mysqli_ston"]`, and `$sqlite_db_connection` are unavailable and do not change the visible source.
2. Step 2 / Trace: In `vulnerabilities/sqli_blind/source/high.php`, line 3 checks `isset($_COOKIE['id'])` → line 5 assigns the cookie value directly to `$id` → line 8 branches on `$_DVWA['SQLI_DB']` → in the MYSQL branch, the exact flagged line 11 is `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";` → line 13 executes that string with `mysqli_query($GLOBALS["___mysqli_ston"], $query)`. The function is still identified only as `<unknown>` in the provided snippet.
3. Step 3 / Validation/Sanitization: No validation, sanitization, encoding, escaping, casting, allowlist, or parameterization is visible between line 5 and the flagged SQL construction on line 11. The `isset` check on line 3 only confirms the cookie exists and is not a SQL injection defense. The additional global context is unavailable, so it provides no visible defense.
4. Step 4 / Sink: The sink is the manually constructed SQL string on flagged line 11, followed by execution on line 13 via `mysqli_query`. The dangerous operation is embedding untrusted `$id` inside a quoted SQL literal without escaping or prepared statements.
5. Step 5 / Framework/Library protections: No framework or ORM protection is visible. `mysqli_query` on line 13 is a raw SQL execution API and does not automatically parameterize interpolated values. The requested database connection globals are unavailable and do not show any automatic protection.
6. Step 6 / Required privilege/authentication: Not visible in provided context. The shown code path requires only that `$_COOKIE['id']` is set on line 3, but authentication, routing, or access-control checks are outside the snippet and remain unavailable.
7. Step 7 / Security impact: If an attacker controls the cookie value, they can modify the SQL query predicate. Because the code reports whether a row exists through different outputs on lines 45-59 and suppresses errors on lines 12-16, the concrete visible impact is blind SQL injection, potentially enabling database data inference/theft or manipulation depending on DB permissions.
8. Step 8 / Weakest link: The weakest link is direct interpolation of untrusted cookie data into SQL on line 11, followed by execution on line 13, with no visible prepared statement, escaping, or validation. No new context supplied a defense that changes this conclusion.
