# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is present and directly interpolates request-controlled `$id` into a SQL query, which is executed by raw `mysqli_query` on the next line. No visible validation, escaping, or parameterization protects this path.

## Data flow

vulnerabilities/sqli/source/low.php:5 `$_REQUEST['id']` → `$id` → vulnerabilities/sqli/source/low.php:10 `$query = "SELECT ... WHERE user_id = '$id';"` → vulnerabilities/sqli/source/low.php:11 `mysqli_query(..., $query)`

## Answers

1. Flagged line located: vulnerabilities/sqli/source/low.php:10 contains exactly `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`. This line is in function `<unknown>` / top-level PHP snippet as provided. The construct described by the rule is present: a manually constructed SQL string interpolating `$id`.
2. Vulnerability class: CWE-89 SQL Injection. The rule identifies tainted user data reaching a SQL string that is later executed.
3. Source: user-controlled request data originates at vulnerabilities/sqli/source/low.php:5, `$id = $_REQUEST[ 'id' ];`. The guard at line 3, `isset($_REQUEST['Submit'])`, is also request-controlled and does not validate `$id`.
4. Data-flow chain: vulnerabilities/sqli/source/low.php:5 `$_REQUEST['id']` → `$id`; vulnerabilities/sqli/source/low.php:10 `$id` interpolated into `$query`; vulnerabilities/sqli/source/low.php:11 `$query` passed to `mysqli_query(...)` for execution. No alloc/free/use chain applies because this is PHP SQL injection, not a memory-lifetime issue.
5. Sanitization/validation: Not visible. There is no cast, allowlist, escaping such as `mysqli_real_escape_string`, or prepared statement between line 5 and line 10.
6. Sink: vulnerabilities/sqli/source/low.php:11 executes the query using `mysqli_query($GLOBALS["___mysqli_ston"], $query)`. The dangerous operation is execution of SQL containing unsanitized user-controlled input.
7. Framework/library protections: No automatic SQL injection protection is visible. Raw `mysqli_query` is used at line 11, not parameterized queries or an ORM.
8. Additional context request: For authentication/route reachability details, the useful context would be `caller:<unknown>` or the enclosing route/controller that includes this file, plus `global:_DVWA` for DB-selection configuration. However, this additional context is not necessary to determine the flagged MySQL sink is SQL-injectable when reached.
