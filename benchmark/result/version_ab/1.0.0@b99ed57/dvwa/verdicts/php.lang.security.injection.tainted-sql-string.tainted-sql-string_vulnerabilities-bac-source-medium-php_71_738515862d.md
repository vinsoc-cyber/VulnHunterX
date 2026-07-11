# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/medium.php:71

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not alter the visible data flow: attacker-controllable `HTTP_X_FORWARDED_FOR` reaches a manually constructed SQL query without escaping or prepared statements. The flagged line begins that SQL string and it is executed by raw `mysqli_query`, making this a clear SQL injection finding.

## Data flow

HTTP request header `$_SERVER['HTTP_X_FORWARDED_FOR']` (vulnerabilities/bac/source/medium.php:69) → assigned to `$ip` without sanitization (line 69) → interpolated into `$log_query` SQL string (lines 71-72) → executed by `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` (line 73)

## Answers

1. Step 0 / Flagged line location: The flagged line 71 is present in `vulnerabilities/bac/source/medium.php` and reads exactly: `$log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES `. It lives in `Function: <unknown>` in the provided snippet. The construct described by the rule is present on that line: it begins a manually constructed SQL string, continued on line 72.
2. Step 1 / Source: The dangerous visible source is `$_SERVER['HTTP_X_FORWARDED_FOR']` on line 69, which comes from an HTTP request header and can be attacker-controlled. `$_SERVER['REMOTE_ADDR']` is also used as a fallback on line 69, but is generally server-derived. The origins of `$id` and `$current_user_id` are still not visible in the provided context.
3. Step 2 / Trace through assignments and transformations: On line 69, `$ip` is assigned from `$_SERVER['HTTP_X_FORWARDED_FOR']` if it is set, otherwise from `$_SERVER['REMOTE_ADDR']`. On line 70, `$target_id` is assigned from `$id` if `$user_exists` is true, otherwise `0`. On lines 71-72, `$current_user_id`, `$target_id`, and `$ip` are interpolated into `$log_query`. On line 73, `$log_query` is passed to `mysqli_query(...)` for execution.
4. Step 3 / Validation, sanitization, encoding: No SQL-specific validation, escaping, prepared statement binding, or encoding is visible for `$ip` before it is interpolated into the SQL string on line 72. No visible cast or escaping is applied to `$target_id` or `$current_user_id` either. The comment on line 68 saying 'only log numeric target_id' is not a runtime validation. The additional requested context was unavailable and does not reveal any upstream defense.
5. Step 4 / Sink: The sink is `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` on line 73. The unsafe operation is executing a manually constructed SQL query from lines 71-72 containing attacker-controllable `$ip` inside SQL quotes.
6. Step 5 / Framework or library protections: No framework or library automatic protection is visible. This is raw `mysqli_query` on line 73, not an ORM or a prepared statement. `mysqli_query` does not automatically escape or parameterize variables already interpolated into a string.
7. Step 6 / Required privilege or authentication state: The exact authentication requirement is not fully visible. Lines 26-47 show a token check for displaying profile information, but the logging block on lines 49-73 appears after that conditional and is not visibly protected by a strong authentication or authorization guard. The additional context did not provide caller/enclosing function details, so no stronger privilege requirement is visible.
8. Step 7 / Security impact: If an attacker controls `HTTP_X_FORWARDED_FOR`, they can inject SQL into the `INSERT INTO bac_log` query on lines 71-73. Concrete impact may include log tampering, arbitrary database modification, or data theft depending on database permissions and whether multi-statements or error-based/boolean/time-based injection techniques are available.
9. Step 8 / Weakest link: The weakest link is the direct interpolation of `$ip` from an HTTP header into a SQL string on line 72, followed by execution through `mysqli_query` on line 73, with no visible escaping, validation, or parameterization. The newly supplied context is unavailable and does not change this analysis.
