# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is visible on line 23 and executes a shell command containing attacker-controlled request data from line 5. The only visible defense is an insufficient blacklist removing `&&` and `;` on lines 8-14, leaving exploitable shell injection vectors, and the added context provides no contrary protection.

## Data flow

HTTP request data `$_REQUEST['ip']` in `vulnerabilities/exec/source/medium.php` line 5 → assigned to `$target` line 5 → partial blacklist replacement via `str_replace()` using substitutions from lines 8-11, applied on line 14 → `$target` concatenated into `'ping  -c 4 ' . $target` on line 23 → command executed by `shell_exec()` on line 23. Additional requested context for `global:$_REQUEST` and `global:$_POST` was unavailable and does not alter the visible flow.

## Answers

1. Step 0 / flagged line location: The exact flagged line is line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule-described construct is present on that line: `shell_exec()` executes a non-constant command string created by concatenating `$target`.
2. Function location: The provided code still shows `Function: <unknown>`. No named PHP function or method wrapper is visible. The flagged line appears to be in top-level script code in `vulnerabilities/exec/source/medium.php`.
3. Step 1: The dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is PHP request data, typically including attacker-controlled GET, POST, and/or cookie parameters. The added context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not show any overriding safety guarantee.
4. Step 2: Data flow trace: line 3 checks whether `$_POST['Submit']` is set; line 5 assigns `$_REQUEST['ip']` to `$target`; lines 8-11 define `$substitutions` as a blacklist for `&&` and `;`; line 14 applies `str_replace(array_keys($substitutions), $substitutions, $target)` and stores the result back into `$target`; line 23 concatenates `$target` into the command string `'ping  -c 4 ' . $target`; line 23 executes that command with `shell_exec()`.
5. Step 3: The only visible validation/sanitization is the blacklist replacement on lines 8-14, which removes `&&` and `;`. This is insufficient for OS command injection because other shell metacharacters and execution forms remain possible, including `|`, single `&`, backticks, `$()`, newlines, redirection, option injection, and other shell parsing behavior. No strict IP validation, allowlist, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, or safe process API is visible.
6. Step 4: The sink is `shell_exec()` on line 23. The dangerous operation is execution of an OS shell command string constructed by concatenating attacker-influenced `$target` into the command.
7. Step 5: No framework or library automatic protection is visible. The additional global context is unavailable and does not add any evidence of request filtering or safe command handling. PHP `shell_exec()` does not automatically escape or parameterize command arguments.
8. Step 6: The visible trigger condition is only `isset($_POST['Submit'])` on line 3. No authentication, authorization, CSRF, or role check is visible in the provided context. Based on the visible code and the scanner-reported request source, an external attacker able to submit request parameters `Submit` and `ip` can reach this path; any stricter auth requirement is not visible.
9. Step 7: If an attacker controls `$_REQUEST['ip']`, the security impact is OS command injection, potentially remote code execution as the PHP/web server process user. This can enable data theft, service compromise, privilege escalation depending on local permissions, or denial of service.
10. Step 8: The weakest link is the incomplete blacklist on lines 8-14 followed by direct string concatenation into `shell_exec()` on line 23. The defense chain is incomplete because it neither validates that `$target` is an IP address nor safely escapes/separates it as a shell argument.
