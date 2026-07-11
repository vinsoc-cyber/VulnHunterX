# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/captcha/source/impossible.php:46

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 1

## Reasoning

The flagged line 46 is present and contains the exact dangerous construct: `if( ( $pass_new == $pass_conf) && ( $data->rowCount() == 1 ) ) {`, including a loose `==` comparison between md5-derived values. User-controlled password inputs are transformed with md5 on lines 14 and 19 and then compared loosely on line 46 without a type-safe comparison, allowing PHP magic-hash type juggling.

## Data flow

$_POST['password_new'] (line 11) → stripslashes (line 12) → mysqli_real_escape_string (line 13) → md5 (line 14) → `$pass_new == $pass_conf` sink (line 46); $_POST['password_conf'] (line 16) → stripslashes (line 17) → mysqli_real_escape_string (line 18) → md5 (line 19) → `$pass_new == $pass_conf` sink (line 46)

## Answers

1. Step 1: The dangerous data originates from user-controlled POST parameters: $_POST['password_new'] on line 11 and $_POST['password_conf'] on line 16. The current password also comes from $_POST['password_current'] on line 21, but the md5 loose-equality issue specifically involves the new password and confirmation values.
2. Step 2: Data flow for the flagged comparison: $_POST['password_new'] line 11 → $pass_new line 11 → stripslashes($pass_new) line 12 → mysqli_real_escape_string(..., $pass_new) line 13 → md5($pass_new) line 14 → loose comparison at line 46. Separately, $_POST['password_conf'] line 16 → $pass_conf line 16 → stripslashes($pass_conf) line 17 → mysqli_real_escape_string(..., $pass_conf) line 18 → md5($pass_conf) line 19 → loose comparison at line 46.
3. Step 3: The code applies stripslashes on lines 12 and 17 and mysqli_real_escape_string on lines 13 and 18. These are not sufficient for the md5 loose-comparison vulnerability because they do not prevent md5 outputs from being numeric-looking strings such as hashes beginning with '0e...'. The md5 transformations on lines 14 and 19 produce hex strings, but PHP loose equality can still type-juggle those strings.
4. Step 4: The sink is the flagged line 46: `if( ( $pass_new == $pass_conf) && ( $data->rowCount() == 1 ) ) {`. The unsafe operation is the loose equality comparison `==` between two md5 hash strings. In PHP, loose comparison can treat numeric-looking strings as numbers, causing distinct md5 hashes like `0e...` values to compare equal.
5. Step 5: PDO parameterization is used for the password lookup and update on lines 40-43 and 48-51, which protects the SQL queries from injection, but it does not protect the md5 comparison at line 46. The CSRF token check on line 5 and CAPTCHA check on lines 27-33 do not mitigate PHP type juggling in the password confirmation comparison.
6. Step 6: The exact authentication state is not fully visible in the provided context. Visible requirements are: the attacker must submit a POST request with `Change` set on line 3, pass the CSRF token check on line 5, pass CAPTCHA on lines 27-33, and satisfy the current-password database check via `$data->rowCount() == 1` on line 46. Because `dvwaCurrentUser()` is used on lines 41 and 50, this appears to target the current user, but the surrounding authentication enforcement is not visible.
7. Step 7: The concrete impact is bypass of the password confirmation check: an attacker who controls both new password fields can choose two different inputs whose md5 hashes are both numeric-looking magic hashes, causing `$pass_new == $pass_conf` to evaluate true at line 46 even though the hashes are not identical. If the current password check also succeeds, the account password is updated on lines 48-51. This is not shown to cause RCE or data theft directly, but it is an authentication/account-integrity flaw.
8. Step 8: The weakest link is the loose comparison operator `==` at line 46. The defense would be complete if the code used strict comparison `===` between `$pass_new` and `$pass_conf`, or compared the raw intended password strings before hashing using strict equality. The visible escaping, CSRF, CAPTCHA, and SQL parameterization do not address this weak link.
