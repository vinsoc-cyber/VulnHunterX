# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the analysis: line 14 clearly executes a shell command containing `$target`, which comes directly from `$_REQUEST['ip']` on line 5. No visible sanitization, escaping, allowlist validation, or automatic framework protection prevents command injection on this path.

## Data flow

HTTP request superglobal `$_REQUEST['ip']` (line 5; additional global context unavailable) → assigned to `$target` (line 5) → no visible sanitization or validation (lines 6-13) → concatenated into command string `'ping  -c 4 ' . $target` (line 14) → executed by `shell_exec()` (line 14)

## Answers

1. Step 0 / flagged line location: The flagged line is line 14: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It is in function `<unknown>` / top-level PHP context as provided. The rule-described construct is present on that line: a non-constant command is built by concatenating `$target` into a string passed to `shell_exec()`.
2. Step 1: The dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST['ip'];`. In PHP, `$_REQUEST` is a request superglobal populated from user-controlled request parameters. The additional context for `global:_REQUEST` is unavailable and does not show any defense or override that changes this.
3. Step 2: Data flow is: user-controlled `$_REQUEST['ip']` on line 5 → assigned directly to `$target` on line 5 → OS check using `php_uname('s')` on line 8 determines branch → in the non-Windows branch, `$target` is concatenated into the command string on line 14 as `'ping  -c 4 ' . $target` → command string is passed to `shell_exec()` on line 14. The added `global:_POST` and `global:_REQUEST` context is unavailable, so it adds no transformation or protection to this chain.
4. Step 3: No validation, sanitization, or encoding is visible at any point between the source and sink. There is no `escapeshellarg()`, `escapeshellcmd()`, strict IP address validation, allowlist, regex constraint, or other visible guard applied to `$target` before line 14. The `isset($_POST['Submit'])` check on line 3 only checks presence of a submit parameter and is not validation of `$_REQUEST['ip']`.
5. Step 4: The sink is `shell_exec()` on line 14. The unsafe operation is executing a shell command string constructed with user-controlled input, allowing shell metacharacters in `$target` to alter the command.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not provide automatic shell argument escaping or parameterization. The additional context does not reveal any configured framework protection.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible. Based only on the provided code, an attacker able to submit a request containing `POST['Submit']` and `REQUEST['ip']` can reach the sink; whether the endpoint is otherwise protected is not visible.
8. Step 7: If the attacker controls `$_REQUEST['ip']`, the impact is command injection and likely remote code execution under the PHP/web-server process privileges. This could also lead to data theft, file modification, lateral movement, or denial of service depending on host permissions.
9. Step 8: The weakest link is the direct concatenation of untrusted request data from line 5 into a shell command executed at line 14 without any visible escaping or allowlist validation. No complete defense is visible in either the original snippet or the added context.
