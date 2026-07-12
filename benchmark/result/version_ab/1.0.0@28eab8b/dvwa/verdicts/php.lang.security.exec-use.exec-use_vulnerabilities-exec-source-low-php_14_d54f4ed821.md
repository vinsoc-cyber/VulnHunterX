# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.99) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is visible and directly executes a shell command containing attacker-controlled request data. Because there is no visible validation or shell escaping on the path from line 5 to line 14, command injection is clearly exploitable.

## Data flow

HTTP request parameter $_REQUEST['ip'] (line 5) → assigned to $target (line 5) → concatenated into shell command string 'ping  -c 4 ' . $target (line 14) → executed by shell_exec() (line 14)

## Answers

1. Flagged line re-quoted: line 14 is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It lives in the top-level PHP script context shown as Function: `<unknown>`, inside the `else` branch for non-Windows systems at lines 12-15.
2. The relevant chain is source-to-sink, not alloc/free/use: `$_REQUEST['ip']` is read on line 5 and assigned to `$target`; `$target` is concatenated into the shell command string on line 14; the resulting command is executed by `shell_exec()` on line 14.
3. The source is attacker-controlled HTTP request data: `$target = $_REQUEST[ 'ip' ];` on line 5. The only visible gate is `isset($_POST['Submit'])` on line 3, which does not validate or sanitize `ip`.
4. No validation, sanitization, escaping, or allowlisting is visible between line 5 and line 14. There is no `escapeshellarg()`, `escapeshellcmd()`, or IP validation such as `filter_var($target, FILTER_VALIDATE_IP)`.
5. The sink is `shell_exec()` on line 14. The unsafe operation is executing a shell command built from a non-constant string containing attacker-controlled input.
6. No framework or library protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments.
7. Additional caller context was already listed as unavailable for `caller:<unknown>`, and the code appears to be top-level PHP. No struct/class/global context is needed to evaluate this direct request-to-shell-execution path.
8. The weakest link is the direct concatenation of `$_REQUEST['ip']` into a shell command without escaping or validation before `shell_exec()`.
