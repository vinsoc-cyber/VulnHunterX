# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context for `global:$_REQUEST` is unavailable and does not alter the visible direct flow from request input at line 5 into `shell_exec()` at line 10. Because the command is constructed by concatenating untrusted data with no visible escaping or validation, the reported tainted-exec command injection finding is clearly present.

## Data flow

vulnerabilities/exec/source/low.php:5 $_REQUEST['ip'] → vulnerabilities/exec/source/low.php:5 assigned to $target → vulnerabilities/exec/source/low.php:8 Windows OS branch condition → vulnerabilities/exec/source/low.php:10 concatenated into 'ping  ' . $target → vulnerabilities/exec/source/low.php:10 executed by shell_exec()

## Answers

1. Step 0 / flagged line location: The flagged line is present at `vulnerabilities/exec/source/low.php:10` and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. The rule-described construct is present on that line: a non-constant command is built by concatenating `$target` into a command string and executed via `shell_exec()`. The code appears to live in function `<unknown>`, i.e. top-level PHP code in the provided snippet.
2. Step 1: The dangerous data originates from user-controlled HTTP request input. Line 5 assigns `$target = $_REQUEST[ 'ip' ];`. The added context for `global:$_REQUEST` is unavailable and does not change this: `$_REQUEST` is a PHP superglobal populated from request data such as GET, POST, and/or COOKIE depending on configuration.
3. Step 2: The data flow is: `$_REQUEST['ip']` at line 5 → assigned directly to `$target` at line 5 → used in the Windows branch after the OS check at line 8 → concatenated into the command string `'ping  ' . $target` at line 10 → passed to `shell_exec()` at line 10. The added context provides no additional transformations or defenses.
4. Step 3: No validation, sanitization, or encoding is visible. Between line 5 and line 10 there is no `escapeshellarg()`, `escapeshellcmd()`, IP address allowlist/validation, regex validation, type constraint, or metacharacter filtering. The added `global:$_REQUEST` context is unavailable and therefore does not show any defense.
5. Step 4: The sink is `shell_exec()` at line 10. The unsafe operation is execution of a shell command string containing user-controlled data. This is dangerous because shell metacharacters in `$target` may be interpreted by the shell as additional commands or command modifiers.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not parameterize shell arguments or automatically escape user input. The added context does not show any framework-level validation, routing guard, or command-escaping wrapper.
7. Step 6: The code path requires `isset($_POST['Submit'])` to be true at line 3 and the Windows branch condition at line 8 to evaluate true. No authentication or authorization requirement is visible in the provided context, so the authentication state required is not visible; however, no auth guard is shown.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete security impact is command injection resulting in arbitrary command execution with the privileges of the PHP/web-server process. This can lead to remote code execution, data theft, privilege escalation within the host context, or denial of service.
9. Step 8: The weakest link is the direct use of request-controlled `$target` from line 5 in a shell command at line 10 without any visible command-argument escaping or strict IP validation. No complete defense is visible in the original snippet or the additional context.
