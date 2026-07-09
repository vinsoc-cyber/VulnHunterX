# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line clearly executes a shell command constructed with user-controlled `$_REQUEST['ip']`, and neither the original snippet nor the provided additional context shows any validation, escaping, or framework protection before `shell_exec()`. The path is visibly reachable when `$_POST['Submit']` is set, making this a command injection issue.

## Data flow

HTTP request parameter $_REQUEST['ip'] (vulnerabilities/exec/source/low.php:5) → assigned directly to $target (line 5) → no visible validation/sanitization; additional global/enclosing context unavailable → concatenated into command string `'ping  ' . $target` (line 10) → executed by shell_exec() sink (line 10)

## Answers

1. Locate flagged line: vulnerabilities/exec/source/low.php:10 is exactly `$cmd = shell_exec( 'ping  ' . $target );`. The rule construct is present on that line: a non-constant command is passed to `shell_exec()` by concatenating `$target` into the shell command.
2. Function/location: the provided context still labels the function as `<unknown>`. The code appears to be top-level PHP script code in `vulnerabilities/exec/source/low.php`, not a named function or method. The requested enclosing route/function context was unavailable, so this does not change the analysis of the visible code.
3. Step 1 source: The dangerous data originates from HTTP request input at vulnerabilities/exec/source/low.php:5: `$target = $_REQUEST[ 'ip' ];`. The additional context for `global:_REQUEST` is unavailable and does not show any sanitization or type guarantee.
4. Step 2 trace: `$_REQUEST['ip']` at vulnerabilities/exec/source/low.php:5 is assigned directly to `$target`; `$target` is then concatenated into the command string at vulnerabilities/exec/source/low.php:10; the resulting non-constant command is passed to `shell_exec()` at vulnerabilities/exec/source/low.php:10. The alternate non-Windows branch similarly uses `$target` in `shell_exec( 'ping  -c 4 ' . $target )` at line 14, but the Semgrep finding specifically flags line 10.
5. Step 3 validation/sanitization: No validation, sanitization, escaping, allowlist, or encoding is visible between line 5 and line 10. There is no `filter_var($target, FILTER_VALIDATE_IP)`, no `escapeshellarg()`, no `escapeshellcmd()`, and no strict IP allowlist. The additional context for `global:_REQUEST`, `global:_POST`, and the enclosing script/route is unavailable and therefore provides no visible defense.
6. Step 4 sink: The sink is `shell_exec()` at vulnerabilities/exec/source/low.php:10. The unsafe operation is execution of an operating-system shell command built from user-controlled request data. Shell metacharacters in `$target` may be interpreted by the shell.
7. Step 5 framework/library protections: No framework or library protection is visible. PHP `shell_exec()` does not automatically escape shell arguments or parameterize commands. The additional context did not reveal any route-level middleware, request validation, authentication guard, or global sanitizer.
8. Step 6 privilege/authentication: The visible trigger condition is `isset( $_POST[ 'Submit' ] )` at line 3. No authentication, authorization, or admin-only check is visible. Based on the provided code, a requester able to send POST data with `Submit` and request parameter `ip` can reach the sink; any external authentication state is not visible.
9. Step 7 impact: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection leading to remote command execution as the PHP/web-server process. This can enable data theft, file modification, service compromise, privilege escalation depending on host permissions, or denial of service.
10. Step 8 weakest link: The weakest link is the direct concatenation of untrusted request input into a shell command at line 10 without visible validation or shell escaping. No complete defense is visible in either the original snippet or the additional context.
