# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/medium.php:21

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged SQL string construction is real, but the only visible tainted value reaching it is `$_GET['user_id']`, which must pass the strict digits-only regex at line 14 before assignment and use. Because that validation excludes SQL metacharacters and syntax on the flagged path, the reported SQL injection is not exploitable in the provided code.

## Data flow

HTTP GET source `$_GET['user_id']` (vulnerabilities/bac/source/medium.php:13) → digits-only whitelist validation `preg_match('/^\d+$/', $_GET['user_id'])` (line 14) → assignment `$id = $_GET['user_id']` (line 17) → SQL string interpolation `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'";` (line 21) → raw query execution `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` (line 22). Additional requested context `global:___mysqli_ston` is unavailable and adds no new data-flow steps.

## Answers

1. Step 0 / flagged line: The flagged line is present at line 21: `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'";`. The construct described by the rule is present on that line: a manually constructed SQL string includes interpolated variable `$id`. The function is labeled `<unknown>` in the provided context, likely top-level PHP page code, but no named enclosing function is visible.
2. Step 1: The potentially dangerous data originates from HTTP GET input: `$_GET['user_id']`, checked at line 13. The additional context for `global:___mysqli_ston` is unavailable and does not change the identified source.
3. Step 2: The data flow is: `$_GET['user_id']` is checked for existence at line 13 → validated with `preg_match('/^\d+$/', $_GET['user_id'])` at line 14 → assigned to `$id` at line 17 → interpolated into `$check_query` at line 21 → executed by `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` at line 22. The additional context provides no new transformations or alternate flows.
4. Step 3: Yes. Line 14 applies validation using `preg_match('/^\d+$/', $_GET['user_id'])`. This is a strict digits-only whitelist, so quotes, whitespace, semicolons, SQL comments, boolean operators, and other SQL syntax cannot pass before assignment to `$id` at line 17. For the specific SQL injection risk at line 21, this visible validation is sufficient.
5. Step 4: The sink is the database query execution at line 22: `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)`, using the SQL string built at line 21. The dangerous operation would be raw execution of an attacker-influenced SQL string, but the attacker-controlled component is constrained to digits before reaching the sink.
6. Step 5: No framework or library automatic protection is visible. `mysqli_query` at line 22 executes a raw SQL string and does not provide automatic parameterization. The requested `global:___mysqli_ston` context is unavailable, so no additional automatic database-layer protection is visible. The only demonstrated protection is the regex whitelist at line 14.
7. Step 6: The path is triggered by an external requester who can supply GET parameters `action` and `user_id` as required by line 13. The snippet references `dvwaCurrentUser()` at line 7, but no explicit authentication or privilege guard is visible. However, the scanner’s source is HTTP GET input, so reachability from external input is established; the decisive issue is exploitability after validation.
8. Step 7: If the value reached SQL without validation, the impact could be SQL injection causing data theft or database manipulation. In this specific flagged path, the visible digits-only validation prevents injection syntax from reaching the SQL string at line 21, so that impact is not concretely exploitable from `$id` here.
9. Step 8: The weakest link is that the code manually constructs SQL instead of using prepared statements. However, for this exact finding, the defense chain is complete enough against SQL injection because line 14 restricts the tainted value to digits before it is interpolated into the query at line 21.
