# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged CWE-78 construct is present: user-controlled `$_REQUEST['ip']` flows directly into `shell_exec()` via string concatenation on lines 10 and 14. No validation, escaping, or framework protection is visible in either the original snippet or the additional context, so an exploitable command-injection path is clearly present when the code is reached.

## Data flow

HTTP request parameter $_REQUEST['ip'] (vulnerabilities/exec/source/low.php:5) → assigned to $target (vulnerabilities/exec/source/low.php:5) → OS branch via php_uname() (vulnerabilities/exec/source/low.php:8) → concatenated into shell command and executed by shell_exec() on Windows (vulnerabilities/exec/source/low.php:10) or non-Windows (vulnerabilities/exec/source/low.php:14) → command output assigned to $cmd (vulnerabilities/exec/source/low.php:10 or :14) → output appended to $html (vulnerabilities/exec/source/low.php:18). Additional requested context for global:$html and bootstrap filtering was unavailable and adds no visible sanitization.

## Answers

1. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` assigned to `$target` on line 5. `$_REQUEST` is a PHP superglobal populated from user-controllable request parameters. The new `global:$html` context is unavailable and does not change this source.
2. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → assigned directly to `$target` on line 5 → concatenated into a shell command in `shell_exec('ping  ' . $target)` on line 10 for Windows or `shell_exec('ping  -c 4 ' . $target)` on line 14 for non-Windows → command output assigned to `$cmd` on lines 10 or 14 → `$cmd` interpolated into `$html` on line 18. The additional context did not reveal any intervening transformation.
3. Step 3: No validation, sanitization, escaping, allowlist checking, or command-argument escaping is visible before the sink. There is no `escapeshellarg()`, `escapeshellcmd()`, `filter_var($target, FILTER_VALIDATE_IP)`, or IP allowlist before lines 10 or 14. The `isset($_POST['Submit'])` check on line 3 only gates execution and does not sanitize `$_REQUEST['ip']`.
4. Step 4: The sink is `shell_exec()` on lines 10 and 14. The dangerous operation is executing a shell command built via string concatenation with attacker-controlled `$target`, which can allow shell metacharacter injection.
5. Step 5: No framework or library protection is visible. The requested bootstrap/request-filtering context was unavailable, and PHP `shell_exec()` does not automatically escape or parameterize command arguments.
6. Step 6: The code path requires `$_POST['Submit']` to be set on line 3 and the attacker to supply `$_REQUEST['ip']` on line 5. Authentication or privilege requirements are not visible in the provided context.
7. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection / remote code execution through `shell_exec()` on lines 10 or 14, running with the privileges of the PHP/web server process.
8. Step 8: The weakest link is the direct concatenation of untrusted request data into a shell command on lines 10 and 14 without visible validation or escaping. No complete defense is visible in the original snippet or the additional context.
