# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 23 clearly executes a non-constant shell command containing `$target`, which is sourced from `$_REQUEST['ip']` on line 5. The only visible defense is an insufficient blacklist on lines 8-14, and the additional context provided no upstream validation or framework protection.

## Data flow

HTTP request input `$_REQUEST['ip']` (line 5) → `$target` assignment (line 5) → incomplete blacklist-only transformation with `str_replace()` removing `&&` and `;` (lines 8-14) → command string concatenation `'ping  -c 4 ' . $target` (line 23) → execution by `shell_exec()` (line 23) → output appended to `$html` (line 27). Additional requested contexts were unavailable and add no visible sanitization or guard.

## Answers

1. Step 0 / flagged line: The flagged line is present at line 23 exactly as `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It is in Function: `<unknown>` / top-level PHP script context in `vulnerabilities/exec/source/medium.php`. The construct described by the rule is present on that line: a non-constant command string is passed to `shell_exec()`.
2. Step 1: The potentially dangerous data originates from HTTP request input: `$target = $_REQUEST['ip'];` on line 5. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not show any defense that changes this.
3. Step 2: The data flow is: `$_REQUEST['ip']` on line 5 → assigned to `$target` on line 5 → `$substitutions` blacklist defined on lines 8-11 → `$target` passed through `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigned on line 14 → OS branch on lines 17-24 → on the non-Windows branch, `$target` is concatenated into `'ping  -c 4 ' . $target` and executed by `shell_exec()` on line 23.
4. Step 3: The only visible sanitization is the blacklist on lines 8-14, which removes `&&` and `;`. This is insufficient for command injection because it does not perform shell argument escaping or strict IP validation, and other shell metacharacters or command-substitution mechanisms may remain possible. No `escapeshellarg()`, `escapeshellcmd()`, `filter_var(..., FILTER_VALIDATE_IP)`, or allowlist validation is visible.
5. Step 4: The sink is `shell_exec()` on line 23. The dangerous operation is executing a shell command built by concatenating user-controlled `$target` into the command string.
6. Step 5: No automatic framework or library protection is visible. The requested additional contexts for globals and enclosing route/controller were unavailable, so they provide no evidence of upstream protection. PHP `shell_exec()` itself does not automatically parameterize or escape shell arguments.
7. Step 6: The code path is gated by `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code or additional context. Therefore, the exact privilege level is not visible, but any requester who can reach this script and set `Submit` and `ip` can trigger the path shown.
8. Step 7: If an attacker controls `$target`, the concrete security impact is command injection, potentially remote code execution as the PHP/web-server process. The command output is also appended to `$html` on line 27, exposing execution results.
9. Step 8: The weakest link is the incomplete blacklist sanitization on lines 8-14. The code removes only two command separators and then directly concatenates request-derived data into `shell_exec()` on line 23; there is no complete visible defense.
