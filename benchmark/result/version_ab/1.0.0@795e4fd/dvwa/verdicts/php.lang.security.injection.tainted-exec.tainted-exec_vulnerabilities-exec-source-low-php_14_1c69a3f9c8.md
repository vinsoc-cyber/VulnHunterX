# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line is present and calls `shell_exec()` with a command string containing `$target`, which comes directly from `$_REQUEST['ip']` with no visible sanitization. The additional context provided is unavailable and does not alter the clear source-to-shell-exec injection path shown in lines 5 and 14.

## Data flow

HTTP request input `$_REQUEST['ip']` (line 5) → assigned directly to `$target` (line 5) → no visible sanitization or validation → concatenated into shell command `'ping  -c 4 ' . $target` (line 14) → executed by `shell_exec()` (line 14). Additional context `global:$html` is unavailable and does not add any visible defense.

## Answers

1. Step 0 / Flagged line: The flagged line is present at line 14 and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the rule-described construct: user-influenced data is concatenated into a shell command passed to PHP `shell_exec()`.
2. Step 1 / Source: The dangerous data originates from HTTP request input: `$target = $_REQUEST[ 'ip' ];` on line 5. The branch is gated by `isset( $_POST[ 'Submit' ] )` on line 3, which is also request-controlled. The new `global:$html` context is unavailable and does not change this source analysis.
3. Step 2 / Trace: `$_REQUEST['ip']` is assigned directly to `$target` on line 5. On non-Windows systems, `$target` is concatenated into the command string `'ping  -c 4 ' . $target` and passed to `shell_exec()` on line 14. On Windows, a similar sink exists on line 10, but the reported flagged line is specifically line 14.
4. Step 3 / Validation/Sanitization/Encoding: No validation, sanitization, encoding, IP address allowlisting, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, or `escapeshellcmd()` is visible between the request source on line 5 and `shell_exec()` on line 14. The additional `global:$html` context is unavailable and shows no defense.
5. Step 4 / Sink: The sink is `shell_exec()` on line 14. The dangerous operation is shell command execution using a string built by concatenating attacker-controlled `$target` into the command.
6. Step 5 / Framework/Library Protections: No framework or library protection is visible. PHP `shell_exec()` does not automatically quote or sanitize concatenated arguments before passing the command to the shell.
7. Step 6 / Privilege/Auth State: Authentication or authorization requirements are not visible in the provided context. The visible code requires only that `$_POST['Submit']` be set on line 3 and that an `ip` request parameter be supplied on line 5.
8. Step 7 / Security Impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell metacharacters into the command executed on line 14, leading to remote command execution as the PHP/web server process user.
9. Step 8 / Weakest Link: The weakest link is direct concatenation of untrusted request input from line 5 into a shell command at line 14 without any visible escaping, validation, or allowlisting. No complete defense is visible in the provided or additional context.
