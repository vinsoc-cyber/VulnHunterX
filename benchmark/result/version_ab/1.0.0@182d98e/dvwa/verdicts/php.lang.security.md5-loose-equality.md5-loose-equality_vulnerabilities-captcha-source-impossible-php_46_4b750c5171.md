# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/captcha/source/impossible.php:46

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 1

## Reasoning

The flagged line 46 contains a loose `==` comparison between two MD5 hash strings derived from user-controlled POST parameters, and the visible transformations do not prevent PHP magic-hash/type-juggling behavior. Although other protections exist for CSRF, CAPTCHA, and SQL queries, none addresses the unsafe comparison at the flagged sink.

## Data flow

source `$_POST['password_new']` (line 11) → `stripslashes` (line 12) → `mysqli_real_escape_string` (line 13) → `md5` (line 14) → sink loose comparison `$pass_new == $pass_conf` (line 46); source `$_POST['password_conf']` (line 16) → `stripslashes` (line 17) → `mysqli_real_escape_string` (line 18) → `md5` (line 19) → sink loose comparison (line 46)

## Answers

1. Step 0 / flagged line: line 46 is exactly `if( ( $pass_new == $pass_conf) && ( $data->rowCount() == 1 ) ) {`. The construct described by the rule is present: `$pass_new` and `$pass_conf` are MD5-derived values from lines 14 and 19 compared with loose equality `==` on line 46.
2. Step 1: The dangerous data originates from user-controlled POST input: `$_POST['password_new']` on line 11 and `$_POST['password_conf']` on line 16. The current password also comes from `$_POST['password_current']` on line 21, but the flagged MD5 loose comparison specifically involves the new and confirmation password values.
3. Step 2: Data flow is: `$_POST['password_new']` line 11 → `$pass_new` → `stripslashes($pass_new)` line 12 → `mysqli_real_escape_string(..., $pass_new)` line 13 → `md5($pass_new)` line 14 → loose comparison on line 46. Separately, `$_POST['password_conf']` line 16 → `$pass_conf` → `stripslashes($pass_conf)` line 17 → `mysqli_real_escape_string(..., $pass_conf)` line 18 → `md5($pass_conf)` line 19 → loose comparison on line 46.
4. Step 3: `stripslashes` is applied on lines 12 and 17, and `mysqli_real_escape_string` is applied on lines 13 and 18. These are not valid defenses for PHP loose-comparison type juggling of MD5 hashes. `md5()` on lines 14 and 19 creates the values being compared, but MD5 hex strings can have the form `0e...`, which PHP may treat as numeric strings under `==`. No strict comparison `===` or other validation excluding magic hashes is visible.
5. Step 4: The sink is the loose equality comparison on line 46: `$pass_new == $pass_conf`. The dangerous operation is PHP type-juggling comparison of two MD5 hash strings using `==` instead of strict equality `===`, allowing distinct hashes that look like scientific notation zero, e.g. `0e...`, to compare equal.
6. Step 5: PDO parameterization is used for the database queries on lines 40-43 and 48-51, which helps prevent SQL injection, but it does not protect the MD5 loose comparison on line 46. The CSRF token check on line 5 and CAPTCHA check on lines 27-33 do not prevent type juggling once the code path is reached.
7. Step 6: The exact authentication requirement is not fully visible in the provided context. The code references `dvwaCurrentUser()` on lines 41 and 50 and checks the current password against the database on lines 40-43, so an attacker would need to reach this password-change handler, pass CSRF/CAPTCHA checks, and satisfy the current-password database check. The broader login/session guard is not visible in the snippet.
8. Step 7: If an attacker controls both password fields, they can make two different password inputs compare as matching after MD5 hashing by using magic-hash values. The direct impact is bypass of the password-confirmation equality check, allowing a password change even when the two submitted new-password fields are not actually the same. The provided code does not show RCE, data theft, or privilege escalation from this sink alone.
9. Step 8: The weakest link is the loose comparison `==` on line 46 between MD5-derived strings from attacker-controlled inputs. Existing defenses address other issues, such as SQL injection via PDO and request legitimacy via CSRF/CAPTCHA, but none prevents PHP type juggling in the MD5 comparison.
