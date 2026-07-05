# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/captcha/source/impossible.php:46

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 1

## Reasoning

The flagged construct is present: two MD5-derived strings from user-controlled POST fields are compared using PHP loose equality at line 46. The visible escaping and CSRF/CAPTCHA/database protections do not prevent PHP type juggling in `==`, and no strict comparison or adequate validation is visible.

## Data flow

source `$_POST['password_new']` (line 11) and `$_POST['password_conf']` (line 16) → `stripslashes` (lines 12, 17) → `mysqli_real_escape_string` (lines 13, 18) → `md5` hashing (lines 14, 19) → loose equality sink `$pass_new == $pass_conf` (line 46) → password update uses `$pass_new` (lines 48-51)

## Answers

1. Step 1: The dangerous data originates from user-controlled POST input: `$_POST['password_new']` at line 11 and `$_POST['password_conf']` at line 16. These are the two values that are later MD5-hashed and compared with loose equality.
2. Step 2: Data flow for the new password: `$_POST['password_new']` line 11 → `$pass_new` line 11 → `stripslashes($pass_new)` line 12 → `mysqli_real_escape_string(..., $pass_new)` line 13 → `md5($pass_new)` line 14 → loose comparison `$pass_new == $pass_conf` line 46 → database update bind as `:password` line 49. Data flow for confirmation password: `$_POST['password_conf']` line 16 → `$pass_conf` line 16 → `stripslashes($pass_conf)` line 17 → `mysqli_real_escape_string(..., $pass_conf)` line 18 → `md5($pass_conf)` line 19 → loose comparison `$pass_new == $pass_conf` line 46.
3. Step 3: `stripslashes` is applied at lines 12 and 17, and `mysqli_real_escape_string` is applied at lines 13 and 18. These are not sufficient for the reported vulnerability because the issue is PHP loose equality/type juggling between MD5 hash strings, not SQL injection or slash escaping. `md5()` is applied at lines 14 and 19, but MD5 can produce strings like `0e...` that PHP may treat as numeric zero during `==` comparison.
4. Step 4: The sink is the loose equality comparison at line 46: `$pass_new == $pass_conf`. The dangerous operation is comparing MD5 hash strings using `==` instead of strict comparison `===`, allowing PHP type juggling where different MD5 hashes that look like scientific notation can compare equal.
5. Step 5: Visible protections include a CSRF token check at line 5, CAPTCHA verification at lines 27-33, and PDO prepared statements for database queries at lines 40-43 and 48-51. These protections do not address the MD5 loose equality issue at line 46. No framework or library protection visible in the provided code converts the comparison to strict string comparison.
6. Step 6: Based on the visible code, an attacker must be able to submit the password change POST request with `Change` set at line 3, pass the CSRF token check at line 5, pass CAPTCHA verification at lines 27-33, and satisfy the current-password database check via `$data->rowCount() == 1` at line 46. Because `dvwaCurrentUser()` is used at lines 41 and 50, this appears to require an authenticated user changing their own password; exact caller/session requirements are not visible in provided context.
7. Step 7: If an attacker controls both password fields, they can cause two different new password inputs to pass the confirmation check if their MD5 hashes trigger PHP loose comparison behavior. The direct impact is authentication/account integrity risk: the application may accept mismatched password confirmation and update the account password to `$pass_new` at lines 48-51. The code does not show RCE or data theft from this specific issue.
8. Step 8: The weakest link is the loose comparison at line 46. Earlier transformations do not validate equality safely, and there is no strict string comparison after MD5 hashing. The complete defense would be to use `===` for the hash comparison, and preferably avoid MD5 for passwords entirely.
