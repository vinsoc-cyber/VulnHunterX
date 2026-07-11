# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is present at line 23 and directly executes a command string containing `$target`, which originates from `$_REQUEST['ip']` on line 5. The only visible defense is an insufficient blacklist removing `&&` and `;` on lines 8-14, leaving a clear exploitable command-injection path.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (line 5) → assigned to `$target` (line 5) → blacklist array removes only `&&` and `;` (lines 8-11) → `str_replace()` applies that incomplete blacklist to `$target` (line 14) → non-Windows branch selected (lines 21-24) → `$target` concatenated into `shell_exec('ping  -c 4 ' . $target)` at the flagged sink (line 23). Additional context `global:$html` is unavailable and does not alter this flow.

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 23 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This is a PHP command-execution sink using `shell_exec()` with a dynamically concatenated command. The metadata says function `<unknown>`; in the provided code it appears to be top-level PHP guarded by the `if` on line 3.
2. Step 1 / source: The dangerous data originates from user-controlled HTTP request input: `$target = $_REQUEST[ 'ip' ];` on line 5. The additional `global:$html` context is unavailable and does not change this answer.
3. Step 2 / trace: `$_REQUEST['ip']` is assigned to `$target` on line 5 → `$substitutions` blacklist is defined on lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → on the non-Windows branch, `$target` is concatenated into the command passed to `shell_exec()` on line 23. The additional context for `$html` does not affect this command-execution data flow.
4. Step 3 / validation/sanitization: The only visible sanitization is a blacklist on lines 8-14 that removes `&&` and `;`. This is insufficient for command injection because other shell metacharacters and command-substitution mechanisms remain possible, including `|`, backticks, `$()`, newlines, redirection, and argument injection. No strict IP allowlist, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, or equivalent protection is visible.
5. Step 4 / sink: The sink is line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is execution of a shell command constructed by concatenating user-controlled input into the command string.
6. Step 5 / framework/library protections: No automatic framework or library protection is visible. PHP `shell_exec()` does not automatically escape or parameterize shell arguments. The unavailable `global:$html` context provides no protection for this sink.
7. Step 6 / privilege/authentication needed: The visible trigger condition is that `$_POST['Submit']` must be set on line 3. No authentication or authorization checks are visible, so the required privilege level is not shown in the snippet. However, any user able to submit this request parameter can reach the sink.
8. Step 7 / impact: If an attacker controls `$_REQUEST['ip']`, they can potentially execute arbitrary OS commands as the PHP/web-server process, resulting in remote code execution, data theft, privilege escalation within the application environment, or denial of service.
9. Step 8 / weakest link: The weakest link is the incomplete blacklist sanitization on lines 8-14 before direct shell execution on line 23. The defense chain is incomplete because it relies on removing only two dangerous tokens instead of enforcing a strict IP format or safely escaping the shell argument.
