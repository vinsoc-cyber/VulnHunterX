# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 10 clearly executes a shell command built from `$target`, which is assigned directly from `$_REQUEST['ip']` on line 5. No escaping, validation, or framework protection is visible before `shell_exec()`, and the added context is unavailable and does not provide any defense.

## Data flow

HTTP request parameter $_REQUEST['ip'] (vulnerabilities/exec/source/low.php:5; global:_REQUEST context unavailable) → direct assignment to $target (line 5) → concatenation into command string `'ping  ' . $target` (line 10, Windows branch) → shell_exec() executes the command (line 10). Alternate path: $target (line 5) → concatenation into `'ping  -c 4 ' . $target` (line 14, non-Windows branch) → shell_exec() executes the command (line 14).

## Answers

1. Step 0 / flagged line location: The exact flagged line is vulnerabilities/exec/source/low.php:10: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command formed by concatenating `$target` into the command string. The code context labels the function as `<unknown>`; the snippet appears to be top-level PHP script code, not inside a visible named function.
2. Q1: The potentially dangerous data originates from HTTP request input at vulnerabilities/exec/source/low.php:5: `$target = $_REQUEST[ 'ip' ];`. The newly provided `global:_REQUEST` context is unavailable and does not change this: `$_REQUEST` is a PHP request superglobal and is attacker-controllable via request parameters depending on PHP configuration.
3. Q2: Data flow trace: `$_REQUEST['ip']` is read at vulnerabilities/exec/source/low.php:5 → assigned directly to `$target` at line 5 → on the Windows branch, `$target` is concatenated into the shell command string `'ping  ' . $target` at line 10 → passed to `shell_exec()` at line 10. On the non-Windows branch, `$target` is concatenated into `'ping  -c 4 ' . $target` and passed to `shell_exec()` at line 14.
4. Q3: No validation, sanitization, or encoding is visible between the source and sink. The code shows no `escapeshellarg()`, `escapeshellcmd()`, IP address validation such as `filter_var($target, FILTER_VALIDATE_IP)`, allowlist, regex validation, or argument separation before `shell_exec()` on lines 10 and 14. The additional `global:_REQUEST` and `global:_POST` context is unavailable and adds no visible defense.
5. Q4: The sink is `shell_exec()` at vulnerabilities/exec/source/low.php:10, with an alternate sink at line 14. The dangerous operation is execution of a shell command string that includes user-controlled data, allowing shell metacharacters or command separators to alter the command executed.
6. Q5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically escape shell arguments or parameterize commands. The additional global context does not show any framework-level validation, routing guard, or automatic protection.
7. Q6: The visible reachability condition is `isset($_POST['Submit'])` at vulnerabilities/exec/source/low.php:3. Authentication or authorization requirements are not visible in the provided context. However, any user who can submit a request reaching this script with `Submit` set and control `ip` can trigger the vulnerable path.
8. Q7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection, potentially arbitrary command execution under the privileges of the PHP/web-server process. This can lead to remote code execution, data theft, service compromise, or denial of service.
9. Q8: The weakest link is direct concatenation of request-controlled `$target` into a shell command at vulnerabilities/exec/source/low.php:10 and line 14 without visible escaping or validation. No complete defense is visible in either the original snippet or the additional context.
