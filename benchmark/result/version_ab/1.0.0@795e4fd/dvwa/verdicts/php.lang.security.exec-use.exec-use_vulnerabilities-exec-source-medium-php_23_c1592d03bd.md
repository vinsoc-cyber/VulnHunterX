# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line executes a non-constant shell command containing request-controlled `$target`. The only visible defense is an incomplete blacklist that does not prevent command injection, and the additional context provided does not reveal any effective upstream validation or protection.

## Data flow

HTTP request input $_REQUEST['ip'] at vulnerabilities/exec/source/medium.php:5 → assigned to $target at line 5 → partial blacklist replacement removes only '&&' and ';' via str_replace at lines 8-14 → non-Windows branch selected at lines 17-23 → $target concatenated into `'ping  -c 4 ' . $target` and executed by shell_exec at line 23. Additional context global:$html is unavailable and does not add any visible sanitization or guard.

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/medium.php:23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This is inside the provided top-level PHP code under the `else` branch for non-Windows systems, not inside a named function; the function is listed as `<unknown>`. The rule-described construct is present: `shell_exec` executes a non-constant command string built by concatenating `$target`.
2. Step 1: The potentially dangerous data originates from HTTP request input: `$target = $_REQUEST[ 'ip' ];` on line 5. `$_REQUEST` can contain user-controlled GET, POST, or cookie data depending on PHP configuration.
3. Step 2: The data flow is: `$_REQUEST['ip']` is assigned to `$target` on line 5; blacklist entries are defined in `$substitutions` on lines 8-11; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; then `$target` is concatenated into the command string `'ping  -c 4 ' . $target` and passed to `shell_exec` on line 23.
4. Step 3: A blacklist sanitization attempt is visible on lines 8-14, removing only `&&` and `;`. This is insufficient for command injection because other shell metacharacters and command execution forms remain possible, such as `|`, single `&`, backticks, `$()`, newlines, redirections, and argument injection. No allowlist IP validation, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg`, or equivalent safe command execution API is visible.
5. Step 4: The sink is `shell_exec` on line 23. The dangerous operation is execution of a shell command constructed by concatenating attacker-controlled `$target` into `'ping  -c 4 ' . $target`.
6. Step 5: No framework or library automatic protection is visible. The additional `global:$html` context is unavailable and does not change the command-execution analysis. PHP `shell_exec` does not automatically escape shell arguments.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided context, so the code appears reachable by any requester who can submit the expected POST parameter. Caller/route context remains not visible, but no visible guard prevents reaching the sink.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the security impact is command injection and potential remote code execution with the privileges of the PHP/web server process. This could lead to data theft, system compromise, lateral movement, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only two command separators but does not constrain the value to a valid IP address and does not safely quote/escape the argument before `shell_exec` on line 23.
