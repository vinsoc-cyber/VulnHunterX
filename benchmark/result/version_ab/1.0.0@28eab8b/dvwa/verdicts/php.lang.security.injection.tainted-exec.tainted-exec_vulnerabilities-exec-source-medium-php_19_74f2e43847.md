# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible and contains a `shell_exec()` call with request-derived `$target`. The complete chain from `$_REQUEST['ip']` to the shell execution sink is shown, and the only visible defense is an inadequate blacklist, so no additional caller, struct, or global context is needed to establish exploitability.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` → assigned to `$target` → vulnerabilities/exec/source/medium.php:14 partial blacklist `str_replace()` removing only `&&` and `;` → vulnerabilities/exec/source/medium.php:19 `$target` concatenated into `'ping  ' . $target` → vulnerabilities/exec/source/medium.php:19 executed by `shell_exec()`; alternate Unix-like path at line 23

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/medium.php:19 and its exact text is `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: user-influenced data is concatenated into a string passed to PHP `shell_exec()`. The enclosing function is not named in the provided context; it is shown as Function: `<unknown>`.
2. Additional context request assessment: No additional caller, struct, or global context is required to evaluate this flagged sink. The source is a PHP superglobal request parameter, the sink is the built-in `shell_exec()`, and the full source-to-sink chain is visible in the snippet. There is no custom callee implementation whose body is needed.
3. Step 1 / source: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` at line 5. The conditional at line 3 only checks `isset($_POST['Submit'])`; it does not validate or authenticate the request.
4. Step 2 / trace: `$_REQUEST['ip']` is assigned to `$target` on line 5. A blacklist array is defined on lines 8-11. `$target` is modified by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14. The resulting `$target` is concatenated into a shell command and passed to `shell_exec()` on line 19 for Windows, and similarly on line 23 for Unix-like systems.
5. Step 3 / validation or sanitization: The only visible transformation is blacklist replacement on line 14, removing only `&&` and `;` as configured on lines 8-11. This is not sufficient for OS command injection because it does not enforce an IP-address allowlist and does not use `escapeshellarg()` or equivalent shell escaping.
6. Step 4 / sink: The sink is `shell_exec()` at line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is shell command execution using a command string containing attacker-controlled input. A parallel sink exists at line 23.
7. Step 5 / framework or library protections: No framework protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments.
8. Step 6 / privilege or authentication state: The visible code requires only that `$_POST['Submit']` be set at line 3. No authentication, authorization, or admin-only guard is visible.
9. Step 7 / impact: Attacker control of `$target` can result in OS command injection / remote command execution under the privileges of the PHP web server process.
10. Step 8 / weakest link: The weakest link is the insufficient blacklist sanitization at line 14 combined with direct concatenation into `shell_exec()` at line 19. The defense is incomplete because it removes only two separators rather than safely escaping or validating the command argument.
