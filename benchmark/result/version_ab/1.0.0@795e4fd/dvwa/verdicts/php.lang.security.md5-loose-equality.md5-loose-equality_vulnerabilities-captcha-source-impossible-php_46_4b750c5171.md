# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/captcha/source/impossible.php:46

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 1

## Reasoning

The flagged line is present and performs a loose `==` comparison between two md5-derived, user-controlled values. The visible transformations do not prevent PHP numeric-string type juggling, and no strict comparison or equivalent validation is present on the flagged path.

## Data flow

source `$_POST['password_new']` (line 11) → `stripslashes` (line 12) → `mysqli_real_escape_string` (line 13) → `md5` (line 14) → loose equality sink `$pass_new == $pass_conf` (line 46); source `$_POST['password_conf']` (line 16) → `stripslashes` (line 17) → `mysqli_real_escape_string` (line 18) → `md5` (line 19) → loose equality sink (line 46)

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 46: `if( ( $pass_new == $pass_conf) && ( $data->rowCount() == 1 ) ) {`. The rule-described construct is present: two values derived from `md5()` are compared using PHP loose equality `==` rather than strict equality `===`.
2. Step 1: The dangerous data originates from user-controlled HTTP POST parameters: `$_POST['password_new']` on line 11 and `$_POST['password_conf']` on line 16. These are the ultimate sources for the two md5 values compared on line 46.
3. Step 2: Data trace: `$_POST['password_new']` line 11 → `$pass_new` → `stripslashes($pass_new)` line 12 → `mysqli_real_escape_string(..., $pass_new)` line 13 → `md5($pass_new)` line 14 → loose comparison on line 46. Separately, `$_POST['password_conf']` line 16 → `$pass_conf` → `stripslashes($pass_conf)` line 17 → `mysqli_real_escape_string(..., $pass_conf)` line 18 → `md5($pass_conf)` line 19 → loose comparison on line 46.
4. Step 3: `stripslashes()` is applied on lines 12 and 17, and `mysqli_real_escape_string()` is applied on lines 13 and 18. These are not sufficient for this vulnerability type because the issue is PHP type juggling during loose comparison of md5 hex strings. No validation is visible that rejects md5 outputs matching PHP numeric-string patterns such as `0e...`, and no strict comparison is used.
5. Step 4: The sink is the loose equality comparison on line 46: `$pass_new == $pass_conf`. This is dangerous because PHP may treat md5 strings that look like scientific notation numbers, such as `0e12345...`, as numeric zero during `==`, causing different md5 hashes to compare equal.
6. Step 5: The PDO prepared statements on lines 40-43 and 48-51 protect the database queries from SQL injection, but they do not protect the md5 comparison on line 46. The CSRF token check on line 5 and CAPTCHA check on lines 27-33 also do not address PHP loose comparison/type juggling. No framework/library protection against this comparison issue is visible.
7. Step 6: The exact authentication state is not fully visible in the provided context. The path requires `$_POST['Change']` to be set on line 3, a valid anti-CSRF token on line 5, a successful CAPTCHA response on lines 27-33, and the current password check to return one row on lines 40-46. The use of `dvwaCurrentUser()` on lines 41 and 50 suggests a current logged-in user context, but the surrounding authentication enforcement is not visible.
8. Step 7: If an attacker controls both new password fields, they can make two different password inputs pass the equality check by using md5 magic-hash values. The direct impact is an integrity/authentication logic bypass of the password confirmation check. The current-password database check on lines 40-46 still gates the update, so the visible impact is not unauthenticated account takeover by itself.
9. Step 8: The weakest link is the loose equality operator `==` on line 46 applied to md5-derived strings from lines 14 and 19. The rest of the defenses shown either address other issues, such as SQL injection or CSRF, or are irrelevant to PHP type juggling. The defense would be complete for this issue if line 46 used strict comparison, e.g. `$pass_new === $pass_conf`.
