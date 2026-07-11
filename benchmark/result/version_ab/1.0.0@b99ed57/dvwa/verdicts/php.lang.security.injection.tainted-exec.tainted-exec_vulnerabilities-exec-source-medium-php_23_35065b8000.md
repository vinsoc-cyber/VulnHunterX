# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and directly executes a shell command containing request-controlled input. The only visible defense is an incomplete blacklist removing `&&` and `;`, while no adequate IP validation, shell escaping, or upstream framework protection is visible in the original or additional context.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (vulnerabilities/exec/source/medium.php:5) → assigned to `$target` (line 5) → partial blacklist removal via `$substitutions` and `str_replace()` removing only `&&` and `;` (lines 8-14) → non-Windows branch selected (lines 21-24) → `$target` concatenated into shell command passed to `shell_exec()` (line 23)

## Answers

1. Step 0 / Flagged line location: The flagged line is present at line 23, exact text: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a shell command built by concatenating `$target`. The provided function is labeled `<unknown>`; the code appears to be top-level PHP in `vulnerabilities/exec/source/medium.php`, and no named enclosing function was provided.
2. Step 1 / Source: The dangerous data originates from HTTP request input on line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` contains user-controllable request parameters. The additional context for `global:$html` and enclosing entrypoint was unavailable and does not change this source identification.
3. Step 2 / Trace: `$_REQUEST['ip']` is assigned to `$target` on line 5 → blacklist entries are defined in `$substitutions` on lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → in the non-Windows branch, `$target` is concatenated into the command string passed to `shell_exec()` on line 23.
4. Step 3 / Validation/Sanitization: Lines 8-14 apply a blacklist that removes only `&&` and `;`. This is not sufficient for shell command injection because other shell metacharacters and constructs remain available, such as `|`, backticks, `$()`, newline, redirection, and option/argument injection. No allowlist IP validation, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, or equivalent shell-safe escaping is visible. The additional context did not provide any upstream validation.
5. Step 4 / Sink: The sink is line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is executing a shell command through PHP `shell_exec()` using a command string concatenated with request-controlled data.
6. Step 5 / Framework/Library protections: No framework or library protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments. The requested additional enclosing route/controller context was unavailable, so there is no visible upstream framework protection that would neutralize the tainted input.
7. Step 6 / Privilege/authentication state: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code or additional context. Based on visible evidence, any requester able to send the relevant POST/request parameters can reach the code path.
8. Step 7 / Security impact: If an attacker controls `$_REQUEST['ip']`, they can cause shell command injection at line 23, resulting in remote command execution as the PHP/web server process user.
9. Step 8 / Weakest link: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only `&&` and `;` instead of enforcing a valid IP address or escaping the value as a shell argument before `shell_exec()`.
