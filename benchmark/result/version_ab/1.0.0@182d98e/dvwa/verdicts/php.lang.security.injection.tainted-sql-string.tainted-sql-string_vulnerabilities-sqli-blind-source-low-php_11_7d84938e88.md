# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/low.php:11

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is present and contains a manually constructed SQL string with user-controlled `$id`. The source-to-sink chain from `$_GET['id']` on line 5 to `mysqli_query` on line 13 is visible, and no sanitization, validation, escaping, or prepared statement is present on that path.

## Data flow

source `$_GET['id']` in `vulnerabilities/sqli_blind/source/low.php:5` → assignment to `$id` at line 5 → interpolation into SQL string `$query` at flagged line 11 → execution via `mysqli_query($GLOBALS["___mysqli_ston"], $query)` at line 13

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 11 and its exact text is: `$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`. This is a manually constructed SQL string with interpolated variable `$id`, matching the rule’s described construct.
2. Function / scope: The provided context labels the function as `<unknown>`. The code appears to be top-level PHP in `vulnerabilities/sqli_blind/source/low.php`, guarded by `if( isset( $_GET[ 'Submit' ] ) )` on line 3.
3. Step 1: The potentially dangerous data originates from user-controlled HTTP GET input: `$_GET['id']` on line 5. Line 3 also shows request-controlled `$_GET['Submit']` controls entry into the block.
4. Step 2: Data flow is: `$_GET['id']` on line 5 → assigned to `$id` on line 5 → interpolated directly into `$query` on flagged line 11 → passed to `mysqli_query($GLOBALS["___mysqli_ston"], $query)` on line 13.
5. Step 3: No validation, sanitization, escaping, type casting, allowlisting, or prepared-statement binding is visible between line 5 and line 13. The assignment on line 5 is direct, and the SQL construction on line 11 directly embeds `$id` inside quotes.
6. Step 4: The sink is SQL execution through `mysqli_query` on line 13, using the manually constructed query from line 11. The dangerous operation is executing SQL containing unsanitized user-controlled input.
7. Step 5: No automatic framework or library protection is visible. This is raw `mysqli_query`, not an ORM or parameterized prepared statement. No visible framework-level SQL escaping or binding applies at line 13.
8. Step 6: Authentication or privilege requirements are not visible in the provided context. The visible reachability condition is only that `$_GET['Submit']` is set on line 3.
9. Step 7: Concrete impact is SQL injection. Because the code performs an existence check and returns distinguishable responses on lines 44-52, this is consistent with blind SQL injection that may allow data inference; broader data theft or manipulation depends on DB privileges and configuration, which are not visible.
10. Step 8: The weakest link is direct interpolation of untrusted `$_GET['id']` into the SQL query at line 11, followed by raw query execution at line 13 without prepared statements or escaping.
11. Additional context request assessment: A caller context is not available because the snippet identifies the function as `<unknown>` and the pre-fetched caller is unavailable. Potentially useful but not necessary context would be `global:$_DVWA` to confirm database branch selection and `global:$GLOBALS["___mysqli_ston"]` for DB connection setup. However, the MySQL branch sink itself and tainted data flow are fully visible.
