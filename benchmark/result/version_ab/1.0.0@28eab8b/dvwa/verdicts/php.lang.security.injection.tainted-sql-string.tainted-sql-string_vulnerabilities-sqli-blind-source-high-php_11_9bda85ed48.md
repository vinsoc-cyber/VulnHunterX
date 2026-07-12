# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible and is a manually constructed SQL query containing `$id`, which comes directly from `$_COOKIE['id']` with no visible sanitization or parameterization before execution. Additional caller or global context could clarify authentication and database configuration, but it is not needed to establish the SQL injection on this flagged path.

## Data flow

vulnerabilities/sqli_blind/source/high.php:3 checks isset($_COOKIE['id']) → vulnerabilities/sqli_blind/source/high.php:5 assigns $_COOKIE['id'] to $id → vulnerabilities/sqli_blind/source/high.php:11 interpolates $id into SQL string `$query` → vulnerabilities/sqli_blind/source/high.php:13 executes `$query` via mysqli_query

## Answers

1. Step 0: The flagged line is present at vulnerabilities/sqli_blind/source/high.php:11 and its exact text is `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";`. This line is in function `<unknown>` / top-level PHP script context as provided. The construct described by the rule is present: a manually constructed SQL string containing interpolated variable `$id`.
2. Step 1: The potentially dangerous data originates from HTTP cookie input: `$_COOKIE['id']` is checked at vulnerabilities/sqli_blind/source/high.php:3 and assigned at line 5. Cookies are user-controlled request data.
3. Step 2: The data flow is: `$_COOKIE['id']` at vulnerabilities/sqli_blind/source/high.php:3/5 → assigned directly to `$id` at line 5 → interpolated into SQL string `$query` at the flagged line 11 → executed with `mysqli_query($GLOBALS["___mysqli_ston"], $query)` at line 13. A sibling SQLite branch also uses `$id` in SQL at line 33 and executes it at line 35, but the flagged sink under review is the MySQL query construction at line 11.
4. Step 3: No validation, sanitization, encoding, escaping, type cast, allowlist, or prepared-statement binding is visible between the cookie read at line 5 and the SQL construction at line 11. Surrounding `$id` with SQL quotes on line 11 is not a sanitizer.
5. Step 4: The sink for the flagged finding is the manual SQL construction at vulnerabilities/sqli_blind/source/high.php:11, followed by execution at line 13 using `mysqli_query`. The dangerous operation is placing attacker-controlled input directly into SQL text.
6. Step 5: No framework or library automatic protection is visible at this point. The code uses raw `mysqli_query` at line 13 with a manually constructed query string from line 11, not a prepared statement or ORM parameterization.
7. Step 6: The exact authentication or privilege state required to reach this script is not visible in the provided snippet. However, the source itself is an HTTP cookie at lines 3 and 5, so an attacker able to reach this code path can supply the relevant data.
8. Step 7: If the cookie value is attacker-controlled, the security impact is SQL injection against the `users` query at line 11, potentially including blind data extraction, bypassing the intended user-id lookup, and database reads/manipulation depending on DB privileges.
9. Step 8: The weakest link is the absence of parameterization or escaping between direct cookie assignment at line 5 and SQL interpolation at line 11. No complete defense is visible in the shown code.
