# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 10 clearly executes a shell command built by concatenating `$target`, which comes directly from `$_REQUEST['ip']` on line 5, with no visible validation, allowlisting, or shell escaping. The additional context is unavailable and does not provide any specific defense that would prevent CWE-78 exploitation on the shown path.

## Data flow

HTTP request condition `$_POST['Submit']` gates execution (vulnerabilities/exec/source/low.php:3) → HTTP request parameter `$_REQUEST['ip']` assigned to `$target` (vulnerabilities/exec/source/low.php:5) → OS branch selected by `stristr(php_uname('s'), 'Windows NT')` (vulnerabilities/exec/source/low.php:8) → `$target` concatenated into command string and executed by `shell_exec()` (vulnerabilities/exec/source/low.php:10; alternate branch line 14). Additional requested contexts `global:$_REQUEST` and `global:$_POST` are unavailable and add no visible sanitization or guard.

## Answers

1. Step 0 / flagged line: The flagged line is vulnerabilities/exec/source/low.php:10: `$cmd = shell_exec( 'ping  ' . $target );`. The rule-described construct is present on that exact line: `$target` is concatenated into a string passed to `shell_exec()`. The code is in function `<unknown>`; from the snippet it appears to be top-level PHP code rather than a named function.
2. Step 1 / source: The dangerous data originates from HTTP request input. `$target` is assigned from `$_REQUEST['ip']` on line 5. The additional context for `global:$_REQUEST` is unavailable, so it does not show any defense or change this source analysis.
3. Step 2 / trace: On line 3, execution is gated by `isset($_POST['Submit'])`. On line 5, `$_REQUEST['ip']` is assigned to `$target`. On line 10, in the Windows branch selected by line 8, `$target` is concatenated into `'ping  ' . $target` and passed to `shell_exec()`. On line 14, in the non-Windows branch, the same `$target` is concatenated into `'ping  -c 4 ' . $target` and passed to `shell_exec()`.
4. Step 3 / validation/sanitization/encoding: No validation, sanitization, escaping, allowlisting, or encoding is visible between the source on line 5 and the sinks on lines 10 and 14. There is no visible `escapeshellarg()`, `escapeshellcmd()`, IP address validation, or allowlist. The additional `global:$_REQUEST` and `global:$_POST` context is unavailable and therefore provides no visible defense.
5. Step 4 / sink: The sink is `shell_exec()` on line 10 for the flagged Windows branch. The alternate branch has the same class of sink on line 14. The dangerous operation is execution of a shell command constructed by concatenating user-controlled `$target` into the command string.
6. Step 5 / framework/library protections: No framework or library protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments. The provided additional context does not show any bootstrap, framework middleware, or global input filtering.
7. Step 6 / required privilege/authentication: The only visible reachability condition is `isset($_POST['Submit'])` on line 3. No authentication, authorization, or admin-only guard is visible in the provided code. The additional context does not show any such guard.
8. Step 7 / impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell metacharacters into the command executed by `shell_exec()` on line 10 or line 14, resulting in OS command injection / potential remote code execution as the PHP/web server process user.
9. Step 8 / weakest link: The weakest link is the direct concatenation of untrusted request data `$target` into a shell command at line 10 without any visible validation or shell escaping. No complete defense is visible in either the original snippet or the additional context.
