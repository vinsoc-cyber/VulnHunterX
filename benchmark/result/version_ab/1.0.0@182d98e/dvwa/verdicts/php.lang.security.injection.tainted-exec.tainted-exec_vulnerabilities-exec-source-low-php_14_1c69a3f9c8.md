# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is present and directly passes request-derived `$target` into `shell_exec()` without any visible escaping or validation. Although caller context could reveal authentication requirements, it would not remove the visible command-injection sink on the reachable code path.

## Data flow

vulnerabilities/exec/source/low.php:5 $_REQUEST['ip'] → vulnerabilities/exec/source/low.php:5 $target → vulnerabilities/exec/source/low.php:14 string concatenation into 'ping  -c 4 ' . $target → vulnerabilities/exec/source/low.php:14 shell_exec()

## Answers

1. Flagged line location: vulnerabilities/exec/source/low.php:14 is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The function context is shown as `<unknown>`; this appears to be top-level PHP code rather than a named function in the provided snippet.
2. The relevant source is HTTP request input at vulnerabilities/exec/source/low.php:5: `$target = $_REQUEST[ 'ip' ];`. This is user-controlled request data.
3. The data flow is vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → assigned to `$target` on line 5 → concatenated into the command string on vulnerabilities/exec/source/low.php:14 → passed to PHP built-in `shell_exec()` on line 14.
4. No validation, sanitization, escaping, type enforcement, or allowlisting is visible between the source on line 5 and the sink on line 14. There is no `escapeshellarg()`, `escapeshellcmd()`, or IP validation such as `filter_var(..., FILTER_VALIDATE_IP)`.
5. The sink is `shell_exec()` at vulnerabilities/exec/source/low.php:14. The dangerous operation is execution of a shell command built by concatenating untrusted input into the command string.
6. The path is reachable when `isset($_POST['Submit'])` is true at vulnerabilities/exec/source/low.php:3 and the OS branch reaches the non-Windows case at lines 12-15. No authentication or authorization check is visible.
7. No additional function body is needed for `shell_exec()` because it is a PHP built-in command-execution sink. Caller context could clarify authentication or routing, but it is not needed to establish the command-injection issue in this snippet.
8. Concrete impact is OS command injection / remote code execution as the PHP/web-server process user if an attacker controls `$_REQUEST['ip']`, because shell metacharacters can be included in `$target` and interpreted by the shell.
