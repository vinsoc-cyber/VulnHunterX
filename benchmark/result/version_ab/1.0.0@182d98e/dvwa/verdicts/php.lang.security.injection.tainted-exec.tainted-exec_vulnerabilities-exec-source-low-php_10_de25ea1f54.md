# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the original source-to-sink analysis: user-controlled `$_REQUEST['ip']` is assigned to `$target` at line 5 and reaches `shell_exec()` at the flagged line 10 with no visible validation, escaping, or parameterization. This is a clear OS command injection / CWE-78 path.

## Data flow

HTTP request superglobal `$_REQUEST['ip']` (vulnerabilities/exec/source/low.php:5; additional global context unavailable) → assigned to `$target` (line 5) → no visible validation/sanitization → concatenated into shell command `'ping  ' . $target` (line 10) → executed by `shell_exec()` (line 10). Sibling branch: `$target` → `'ping  -c 4 ' . $target` (line 14) → `shell_exec()` (line 14).

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/low.php:10 and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. It is in top-level PHP script scope / function `<unknown>`. The construct described by the rule is present on that line: a shell execution function, `shell_exec()`, receives a command string concatenated with `$target`.
2. Step 1: The dangerous data originates from HTTP request input at vulnerabilities/exec/source/low.php:5: `$target = $_REQUEST[ 'ip' ];`. The additional context for `global:$_REQUEST` is unavailable, so it does not change this answer. In PHP, `$_REQUEST` is a request superglobal and is user-controlled depending on request parameters/configuration.
3. Step 2: Data flow is `$_REQUEST['ip']` at vulnerabilities/exec/source/low.php:5 → assigned directly to `$target` at line 5 → used without modification in the Windows branch command string at line 10: `'ping  ' . $target` → executed by `shell_exec()` at line 10. The same `$target` also flows to the Unix-like branch at line 14: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`.
4. Step 3: No validation, sanitization, or encoding is visible between source and sink. There is no visible IP allowlist, `filter_var($target, FILTER_VALIDATE_IP)`, regex validation, `escapeshellarg()`, `escapeshellcmd()`, or argument-array API before the `shell_exec()` calls at lines 10 and 14. The additional global context is unavailable and provides no visible defense.
5. Step 4: The sink is `shell_exec()` at vulnerabilities/exec/source/low.php:10, with a sibling sink at line 14. The dangerous operation is execution of a shell command built through string concatenation with attacker-controlled request data.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically escape or parameterize shell arguments. The newly provided context for `$_REQUEST` and `$_POST` is unavailable and shows no automatic protection or configuration that would neutralize the issue.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` at vulnerabilities/exec/source/low.php:3. The additional context for `global:$_POST` is unavailable, so it does not show any authentication or authorization requirement. Based on visible code, any requester able to supply POST parameter `Submit` and request parameter `ip` can reach the sink; authentication state is not visible.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection leading to remote code execution with the privileges of the PHP/web-server process. For example, shell metacharacters in `ip` could append or alter commands executed by `shell_exec()`.
9. Step 8: The weakest link is the direct concatenation of untrusted request input into a shell command at vulnerabilities/exec/source/low.php:10, and also line 14, without validation or shell escaping. No complete defense is visible in either the original snippet or the additional context.
