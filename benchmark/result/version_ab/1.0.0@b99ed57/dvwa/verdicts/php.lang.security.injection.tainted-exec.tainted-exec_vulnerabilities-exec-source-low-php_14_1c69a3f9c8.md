# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

Although the enclosing named function is not visible and is labeled `<unknown>`, the complete relevant source-to-sink chain for this finding is visible in the snippet. The exact flagged line executes a shell command containing user-controlled `$_REQUEST['ip']` with no visible validation or shell escaping, making this a clear command injection vulnerability.

## Data flow

vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → vulnerabilities/exec/source/low.php:5 assigned to `$target` → vulnerabilities/exec/source/low.php:14 concatenated into `'ping  -c 4 ' . $target` → vulnerabilities/exec/source/low.php:14 executed by `shell_exec()`

## Answers

1. Step 0: The flagged line is present at line 14 and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a shell command string that includes the variable `$target`. The enclosing function is shown as `<unknown>` in the provided context; the code appears to be top-level PHP script code rather than a named function.
2. Step 1: The potentially dangerous data originates from HTTP request input on line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is user-controllable request data.
3. Step 2: The data flow is fully visible in the snippet: `$_REQUEST['ip']` on line 5 is assigned directly to `$target`; `$target` is concatenated directly into the command string passed to `shell_exec()` on line 14.
4. Step 3: No validation, sanitization, escaping, allowlisting, type enforcement, or IP-address validation is visible between line 5 and line 14. Specifically, there is no `escapeshellarg()`, `escapeshellcmd()`, or `filter_var(..., FILTER_VALIDATE_IP)` before the sink.
5. Step 4: The sink is `shell_exec()` on line 14. The dangerous operation is execution of a shell command constructed by concatenating untrusted input into the command string.
6. Step 5: No framework or library protection is visible. PHP `shell_exec()` does not automatically escape shell metacharacters or parameterize arguments.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible in the provided code. Based only on this context, any requester able to reach this script and submit the required POST field can trigger the path.
8. Step 7: The concrete security impact is OS command injection / remote command execution. For example, if `$target` contains shell metacharacters, it can alter the command executed by `shell_exec()` on line 14.
9. Step 8: The weakest link is the direct concatenation of untrusted request data from line 5 into a shell command on line 14 without any visible escaping or validation.
