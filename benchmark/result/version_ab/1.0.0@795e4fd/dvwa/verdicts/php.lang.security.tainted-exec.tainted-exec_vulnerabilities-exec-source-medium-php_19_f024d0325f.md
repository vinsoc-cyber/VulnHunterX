# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional global context is unavailable and does not change the analysis: the visible path takes request-controlled `$_REQUEST['ip']`, applies only an incomplete blacklist, and concatenates it into `shell_exec()` on the exact flagged line 19. Because no adequate validation, escaping, or framework protection is visible on this path, this is a clear tainted command execution vulnerability.

## Data flow

HTTP request input `$_REQUEST['ip']` (line 5; global context unavailable) → `$target` assignment (line 5) → incomplete blacklist `str_replace(...)` removing only `&&` and `;` (lines 8-14) → concatenation into `shell_exec('ping  ' . $target)` on flagged line 19

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 19 and is exactly: `$cmd = shell_exec( 'ping  ' . $target );`. This line contains the rule-described construct: `shell_exec()` executes a non-constant command formed by concatenating `$target`. The provided code is top-level PHP code with Function: `<unknown>`, not inside a visible named function.
2. Step 1: The potentially dangerous data originates from HTTP request input: `$_REQUEST['ip']` is assigned to `$target` on line 5. The additional context for `global:$_REQUEST` is unavailable and does not show any constraint or sanitizer that would change this.
3. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → `$target` assignment on line 5 → blacklist array `$substitutions` defined on lines 8-11 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → `$target` concatenated into the command string in `shell_exec('ping  ' . $target)` on flagged line 19. There is also a non-Windows sibling sink at line 23: `shell_exec('ping  -c 4 ' . $target)`.
4. Step 3: The only visible validation/sanitization is a blacklist on lines 8-14 that removes only `&&` and `;`. This is not sufficient for OS command injection because it is not strict IP validation and does not use `escapeshellarg()` or equivalent shell argument escaping. The newly provided global contexts for `$_REQUEST`, `$_POST`, and `$html` are unavailable and provide no additional visible sanitizer or validation.
5. Step 4: The sink is `shell_exec()` on line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is executing a shell command string constructed with request-derived data.
6. Step 5: No framework or library automatic protection is visible. `shell_exec()` does not parameterize or safely escape command arguments. The additional context does not reveal any framework-level request validation, routing constraint, or auto-protection.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible in the provided code or additional context, so the required privilege level is not shown; based on visible code, any requester able to submit the expected POST parameter can reach the path.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection, potentially remote command execution as the PHP/web server process. The command output is captured in `$cmd` on line 19 and emitted into `$html` on line 27.
9. Step 8: The weakest link is the incomplete blacklist replacement on lines 8-14 before direct shell command construction on line 19. No complete defense is visible: there is no allowlist IP validation, no shell escaping, and no parameterized command execution API.
