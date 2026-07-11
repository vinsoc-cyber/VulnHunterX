# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not change the visible data flow: user-controlled `$_REQUEST['ip']` reaches `shell_exec()` on line 19 after only an insufficient blacklist. Because there is no visible strict IP validation or shell escaping before the command execution sink, the flagged path is clearly vulnerable to OS command injection.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (vulnerabilities/exec/source/medium.php:5) → assigned to `$target` (line 5) → partially transformed by `str_replace()` blacklist removing only `&&` and `;` (lines 8-14) → concatenated into `shell_exec('ping  ' . $target)` on the Windows branch (line 19)

## Answers

1. Step 0: The flagged line 19 is present and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: data in `$target` is concatenated into a string passed to `shell_exec()`. The code is in `vulnerabilities/exec/source/medium.php`; no named function is shown, so it appears to be top-level script code.
2. Step 1: The dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. The additional requested context for `global:$_REQUEST` was unavailable and does not change this; in PHP, `$_REQUEST` is a superglobal populated from request parameters.
3. Step 2: Data flow: `$_REQUEST['ip']` is read and assigned to `$target` on line 5 → blacklist entries are defined in `$substitutions` on lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → OS branch is selected at line 17 → on Windows, `$target` is concatenated into the command passed to `shell_exec()` on line 19. A similar non-Windows sink is visible on line 23, but the flagged line is line 19.
4. Step 3: The only visible sanitization is the blacklist on lines 8-14, which removes only `&&` and `;`. This is not sufficient for OS command injection because the value is still unquoted and unescaped when passed to the shell, and other shell metacharacters or command-substitution mechanisms remain possible, such as `|`, single `&`, `||`, backticks, `$()`, or newlines depending on shell/platform. No `escapeshellarg()`, `escapeshellcmd()`, or strict IP validation such as `filter_var(..., FILTER_VALIDATE_IP)` is visible.
5. Step 4: The sink is `shell_exec()` at line 19: `$cmd = shell_exec( 'ping  ' . $target );`. This is dangerous because it executes a shell command constructed by concatenating user-controlled request data.
6. Step 5: No framework or library automatic protection is visible. The additional context requests for globals, caller, and enclosing script were unavailable and therefore do not add any evidence of upstream validation or protection. PHP `shell_exec()` does not automatically escape shell arguments.
7. Step 6: The visible trigger condition is line 3: `if( isset( $_POST[ 'Submit' ]  ) )`. No authentication or authorization check is visible in the provided code or added context. Based on the visible code, an attacker who can send a request with `POST['Submit']` and `REQUEST['ip']` can trigger the path.
8. Step 7: The concrete security impact is OS command injection leading to remote command execution as the PHP/web server process, with potential data theft, server compromise, privilege escalation from the web user context, or denial of service.
9. Step 8: The weakest link is the inadequate blacklist on lines 8-14 followed by direct shell execution on line 19. The defense is incomplete because it removes only two separators and does not enforce that `$target` is a valid IP address or escape it as a shell argument.
