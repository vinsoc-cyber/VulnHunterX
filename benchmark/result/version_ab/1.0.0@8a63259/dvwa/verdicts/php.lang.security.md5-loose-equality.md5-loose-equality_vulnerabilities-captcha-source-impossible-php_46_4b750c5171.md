# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/captcha/source/impossible.php:46

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 1

## Reasoning

The flagged line is present and reads exactly: if( ( $pass_new == $pass_conf) && ( $data->rowCount() == 1 ) ) {, which contains the rule-described loose equality comparison involving md5-derived values. User-controlled password fields are transformed into md5 strings on lines 14 and 19 and compared with == on line 46, with no visible strict comparison or validation preventing PHP magic-hash type juggling.

## Data flow

$_POST['password_new'] (line 11) → stripslashes (line 12) → mysqli_real_escape_string (line 13) → md5 (line 14) → $pass_new == $pass_conf loose comparison (line 46); $_POST['password_conf'] (line 16) → stripslashes (line 17) → mysqli_real_escape_string (line 18) → md5 (line 19) → $pass_new == $pass_conf loose comparison (line 46)

## Answers

1. Step 1: The dangerous data originates from user-controlled POST parameters: $_POST['password_new'] on line 11 and $_POST['password_conf'] on line 16. These are ultimate sources controlled by the requester submitting the password change form.
2. Step 2: password_new flow: $_POST['password_new'] line 11 → stripslashes($pass_new) line 12 → mysqli_real_escape_string(..., $pass_new) line 13 → md5($pass_new) line 14 → loose comparison $pass_new == $pass_conf line 46. password_conf flow: $_POST['password_conf'] line 16 → stripslashes($pass_conf) line 17 → mysqli_real_escape_string(..., $pass_conf) line 18 → md5($pass_conf) line 19 → loose comparison $pass_new == $pass_conf line 46.
3. Step 3: stripslashes is applied on lines 12 and 17, and mysqli_real_escape_string is applied on lines 13 and 18. These are not sufficient for this vulnerability type because the issue is PHP loose equality/type juggling between md5 hex strings, not SQL injection or slash escaping. md5 is applied on lines 14 and 19, but md5 can produce strings such as numeric-looking '0e...' hashes that compare equal under == in PHP.
4. Step 4: The sink is the loose equality comparison on line 46: if( ( $pass_new == $pass_conf) && ( $data->rowCount() == 1 ) ). The dangerous operation is using == instead of === to compare md5-derived strings, allowing PHP type juggling of numeric-looking hash strings.
5. Step 5: Visible framework/library protections include checkToken on line 5, reCAPTCHA verification on lines 27-33, and PDO prepared statements with bound parameters on lines 40-43 and 48-51. These protect against CSRF, automated submission, and SQL injection respectively, but they do not protect the md5 loose comparison on line 46. No visible library or framework protection enforces strict hash comparison here.
6. Step 6: The code path requires a POST request with $_POST['Change'] set on line 3, a valid CSRF token checked on line 5, successful CAPTCHA on lines 27-33, and the current password hash matching a database row via rowCount() == 1 on lines 40-46. The use of dvwaCurrentUser() on lines 41 and 50 suggests an authenticated user context, but the surrounding authentication enforcement is not visible in provided context.
7. Step 7: If an attacker controls password_new and password_conf, they can make two different plaintext passwords with md5 hashes that are both numeric-looking strings compare equal under PHP loose equality. The concrete impact in this snippet is bypassing the intended new-password confirmation check and causing the application to update the current user's password to $pass_new on lines 48-51 despite $pass_new and $pass_conf representing different plaintext values. This is an authentication/account-integrity flaw, not RCE or data theft from the visible code.
8. Step 8: The weakest link is the loose comparison on line 46 between md5-derived values from user input. The preceding transformations on lines 12-14 and 17-19 do not validate against magic md5 hashes or enforce string identity, and the visible CSRF/CAPTCHA/SQL protections do not address PHP type juggling. The complete defense would be a strict comparison using === or a password-hashing/verification API.
