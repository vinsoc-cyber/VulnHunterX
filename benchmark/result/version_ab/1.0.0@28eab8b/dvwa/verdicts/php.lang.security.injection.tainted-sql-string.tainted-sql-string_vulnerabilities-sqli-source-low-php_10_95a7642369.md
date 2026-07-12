# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and clearly constructs SQL using `$id` from `$_REQUEST['id']` with no visible validation or parameterization before execution by `mysqli_query`. Additional caller, struct, or global context is not necessary to establish this specific SQL injection path because the remote source, unsafe construction, and execution sink are all present in the provided code.

## Data flow

vulnerabilities/sqli/source/low.php:5 `$_REQUEST['id']` → vulnerabilities/sqli/source/low.php:5 `$id` → vulnerabilities/sqli/source/low.php:10 `$query = "SELECT ... user_id = '$id';"` → vulnerabilities/sqli/source/low.php:11 `mysqli_query(..., $query)`

## Answers

1. Step 0 / flagged line: The flagged line is line 10: `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`. The construct described by the rule is present on that exact line: a manually constructed SQL string interpolating `$id`.
2. Function location: The code context labels the function as `<unknown>`, and the snippet appears to be top-level PHP code guarded by `if (isset($_REQUEST['Submit']))` on line 3. No named enclosing function is visible.
3. Step 1 / source: The dangerous data originates from HTTP request input, specifically `$_REQUEST['id']` on line 5. The code path is request-triggered by `isset($_REQUEST['Submit'])` on line 3.
4. Step 2 / trace: `$_REQUEST['id']` is assigned directly to `$id` on line 5. `$id` is interpolated directly into `$query` on line 10. `$query` is executed with `mysqli_query(...)` on line 11.
5. Step 3 / validation or sanitization: No validation, sanitization, escaping, casting, allowlist, or parameter binding is visible between line 5 and line 10. The value is placed inside SQL quotes, but that is not a defense against SQL injection.
6. Step 4 / sink: The immediate flagged construction sink is line 10, where tainted data is embedded into SQL. The execution sink is line 11: `mysqli_query($GLOBALS["___mysqli_ston"], $query)`, which runs the raw SQL string.
7. Step 5 / framework or library protections: No ORM, prepared statement, parameterized query, or automatic SQL escaping is visible. `mysqli_query` executes the raw query string; it does not automatically parameterize interpolated values.
8. Step 6 / privilege or authentication needed: The only visible requirement is that `$_REQUEST['Submit']` be set on line 3. Authentication or authorization is not visible in the provided context. The source is remote HTTP request data.
9. Step 7 / impact: An attacker controlling `$id` can alter the SQL query, potentially reading unauthorized rows from the `users` table and, depending on database permissions and configuration, extracting or manipulating additional data.
10. Step 8 / weakest link: The weakest link is the direct interpolation of unsanitized `$_REQUEST['id']` into a SQL query on line 10 followed by raw execution on line 11.
