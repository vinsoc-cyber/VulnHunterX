# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 19 executes a shell command constructed from `$_REQUEST['ip']`, and the only visible defense is an incomplete blacklist that does not prevent command injection. The additional context did not reveal any upstream validation, framework protection, or safe command construction, so the flagged sink is exploitable on the visible path.

## Data flow

HTTP request parameter `$_REQUEST['ip']` at vulnerabilities/exec/source/medium.php:5 → assigned to `$target` at line 5 → partial blacklist substitutions defined at lines 8-11 → `$target` transformed by `str_replace(...)` at line 14, removing only `&&` and `;` → Windows OS branch at line 17 → concatenated into shell command and executed by `shell_exec('ping  ' . $target)` at line 19. Additional requested globals were unavailable and add no visible sanitization or protection.

## Answers

1. Step 0 / flagged line location: The flagged line is present at vulnerabilities/exec/source/medium.php:19 and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. The Semgrep-described construct is present on that line: `shell_exec()` executes a non-constant command created by concatenating `$target`.
2. Step 1: The dangerous data originates from HTTP request input: `$target = $_REQUEST[ 'ip' ];` at line 5. In PHP, `$_REQUEST` is user-controllable request data derived from GET/POST/cookie parameters depending on configuration.
3. Step 2: The data flow is: `$_REQUEST['ip']` is assigned to `$target` at line 5 → blacklist substitutions are defined at lines 8-11 → `$target` is transformed with `str_replace(array_keys($substitutions), $substitutions, $target)` at line 14 → the Windows branch is selected by `stristr(php_uname('s'), 'Windows NT')` at line 17 → `$target` is concatenated into the command passed to `shell_exec()` at line 19.
4. Step 3: There is partial blacklist sanitization at lines 8-14, removing only `&&` and `;`. This is not sufficient for command injection prevention because other shell metacharacters/operators remain possible, especially on the Windows branch flagged at line 19, such as single `&`, `|`, redirection, newline-based command separation, and other shell parsing tricks. No allowlist IP validation, `escapeshellarg()`, `escapeshellcmd()`, or equivalent safe command construction is visible.
5. Step 4: The sink is `shell_exec()` at line 19. The unsafe operation is execution of a shell command string built from attacker-controlled input: `'ping  ' . $target`.
6. Step 5: The additional context for `global:$html` and `global:$_REQUEST` is unavailable and does not show any new protection. No framework-level protection, automatic shell escaping, command parameterization, or upstream validation is visible. PHP `shell_exec()` itself does not provide automatic argument escaping.
7. Step 6: The visible trigger condition is only `isset($_POST['Submit'])` at line 3. No authentication or authorization requirement is visible in the provided code or additional context. Based only on visible code, an attacker needs the ability to submit a request with `POST['Submit']` set and provide `ip` in request data.
8. Step 7: The concrete impact is command injection leading to command execution/RCE in the security context of the PHP/web server process. This may enable data theft, file modification, service disruption, or further compromise depending on process privileges.
9. Step 8: The weakest link is the blacklist-based defense at lines 8-14. It removes only two command separators and fails to constrain the value to a valid IP address or safely escape it before the command-execution sink at line 19.
