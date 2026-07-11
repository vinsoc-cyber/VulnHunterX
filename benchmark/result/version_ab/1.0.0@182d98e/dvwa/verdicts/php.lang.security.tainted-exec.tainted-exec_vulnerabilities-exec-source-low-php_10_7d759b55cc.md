# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not reveal any sanitizer, validation, access-control guard, or framework protection. The visible code clearly sends user-controlled `$_REQUEST['ip']` from line 5 directly into `shell_exec()` at the flagged line 10 without escaping, creating an exploitable command-injection sink.

## Data flow

`$_REQUEST['ip']` user input (`vulnerabilities/exec/source/low.php:5`) → assigned to `$target` (`vulnerabilities/exec/source/low.php:5`) → no visible validation/sanitization (`vulnerabilities/exec/source/low.php:6-9`) → concatenated into shell command and executed by `shell_exec('ping  ' . $target)` (`vulnerabilities/exec/source/low.php:10`)

## Answers

1. Step 0 / flagged line: The flagged line is present at `vulnerabilities/exec/source/low.php:10` and its exact text is `$cmd = shell_exec( 'ping  ' . $target );`. This line contains the rule-described construct: execution of a non-constant shell command via `shell_exec()` with concatenated variable data. The code is in function `<unknown>`; based on the snippet, it appears to be top-level PHP script code rather than a named function.
2. Step 1: The potentially dangerous data originates from HTTP request/user input at line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is a PHP superglobal containing user-controlled request data. The added context for `global:_REQUEST` and `global:_POST` is unavailable and does not change this answer.
3. Step 2: Data flow is: user-controlled `$_REQUEST['ip']` at line 5 → assigned directly to `$target` at line 5 → `$target` is concatenated into the command argument to `shell_exec()` at the flagged line 10 in the Windows branch. The same `$target` also flows to another `shell_exec()` call on line 14 in the Unix-like branch, but the flagged sink is line 10.
4. Step 3: No validation, sanitization, escaping, or encoding is visible between source line 5 and sink line 10. There is no `escapeshellarg()`, `escapeshellcmd()`, IP allowlist, regex validation, or `filter_var($target, FILTER_VALIDATE_IP)` before execution. The added context provides no upstream sanitizer or validation.
5. Step 4: The sink is `shell_exec()` at line 10: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is passing a shell command string built by concatenating untrusted request data into an OS command execution function.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically quote or escape shell metacharacters. The additional context for callers/includes is unavailable and shows no framework-level protection.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` at line 3. No authentication or authorization check is visible in the provided code. Therefore, based on the visible code, an attacker only needs the ability to send a request setting `POST['Submit']` and supplying `REQUEST['ip']`; no authenticated or admin-only requirement is shown.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, they can inject shell metacharacters into the command executed at line 10, leading to OS command injection / remote code execution as the PHP/web-server process user. Potential impact includes arbitrary command execution, data theft, file modification, and denial of service.
9. Step 8: The weakest link is direct concatenation of untrusted request input into `shell_exec()` at line 10 without any visible command-argument escaping or input validation. No complete defense is visible in the original snippet or the additional context.
