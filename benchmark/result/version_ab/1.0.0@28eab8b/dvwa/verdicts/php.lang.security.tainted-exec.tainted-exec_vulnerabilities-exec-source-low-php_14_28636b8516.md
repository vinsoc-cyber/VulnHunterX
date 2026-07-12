# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible and contains the reported sink: `$cmd = shell_exec( 'ping  -c 4 ' . $target );` at line 14. The attacker-controlled request value from line 5 reaches `shell_exec()` with no visible validation or shell escaping, so the command injection path is clearly present and exploitable.

## Data flow

vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → vulnerabilities/exec/source/low.php:5 assigned to `$target` → vulnerabilities/exec/source/low.php:14 concatenated into `'ping  -c 4 ' . $target` → vulnerabilities/exec/source/low.php:14 executed by `shell_exec()`

## Answers

1. Flagged line location: line 14 is present and marked in the provided code. Exact text: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a dynamically concatenated command containing `$target`.
2. Function/container: The snippet is top-level PHP code; the reported function is `<unknown>`. No named enclosing function is visible in the provided context.
3. Source: The dangerous data originates from HTTP request input at `vulnerabilities/exec/source/low.php:5`, where `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST['ip']` is externally controllable request data.
4. Data-flow trace: `$_REQUEST['ip']` at line 5 is assigned directly to `$target`; `$target` is then concatenated into the command string at line 14; the resulting command is passed to `shell_exec()` at line 14.
5. Validation/sanitization: No validation, sanitization, escaping, or allowlisting is visible between line 5 and line 14. There is no `escapeshellarg()`, `escapeshellcmd()`, `filter_var(..., FILTER_VALIDATE_IP)`, regex allowlist, or equivalent protection.
6. Sink: The sink is `shell_exec()` at line 14. The dangerous operation is execution of a shell command string built using attacker-controlled data.
7. Framework/library protections: Not visible in provided context. PHP `shell_exec()` does not automatically escape shell metacharacters or parameterize command arguments.
8. Reachability/privilege: The visible gate is `isset($_POST['Submit'])` at line 3. No authentication, authorization, or admin-only guard is visible. Because the source is an HTTP request variable, the scanner has established external taint reachability; exploitability depends on the absence of sanitization, which is visible here.
9. Impact: An attacker controlling `$_REQUEST['ip']` can inject shell metacharacters into the command at line 14, leading to OS command injection / remote code execution as the PHP/web-server process user.
10. Weakest link: The weakest link is direct concatenation of untrusted request input into a shell command at line 14 without escaping or validation.
