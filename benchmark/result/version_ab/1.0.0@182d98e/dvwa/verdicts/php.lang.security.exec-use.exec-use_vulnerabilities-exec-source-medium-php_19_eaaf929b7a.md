# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is visible at line 19 and directly executes a command containing user-controlled input from line 5. The only visible mitigation is an insufficient blacklist on lines 8-14, with no complete validation or escaping before `shell_exec()`.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` → `$target`; vulnerabilities/exec/source/medium.php:8-11 blacklist defines only `&&` and `;`; vulnerabilities/exec/source/medium.php:14 `str_replace()` partially modifies `$target`; vulnerabilities/exec/source/medium.php:19 `$target` is concatenated into `ping` and executed by `shell_exec()`

## Answers

1. Step 0 / Flagged line: line 19 is exactly `$cmd = shell_exec( 'ping  ' . $target );`. The reported construct is present on that line: `shell_exec()` executes a non-constant command built by concatenating `$target`. The function is listed as `<unknown>`; based on the snippet, this appears to be top-level PHP script code rather than a named function.
2. Step 1 / Source: The potentially dangerous data originates from user-controlled request input: `$target = $_REQUEST[ 'ip' ];` on line 5. The code is gated only by `isset( $_POST[ 'Submit' ] )` on line 3.
3. Step 2 / Trace: `$_REQUEST['ip']` is assigned to `$target` on line 5. `$substitutions` is defined on lines 8-11. `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14. The transformed `$target` is concatenated into the shell command on line 19 in the Windows branch, and line 23 in the non-Windows branch.
4. Step 3 / Validation or sanitization: The only visible sanitization is blacklist replacement on line 14, removing `&&` and `;` as configured on lines 8-11. This is not sufficient command-injection protection because the code does not validate that the input is an IP address and does not use `escapeshellarg()`, `escapeshellcmd()`, or a safe argument-vector API before `shell_exec()`.
5. Step 4 / Sink: The sink is `shell_exec( 'ping  ' . $target )` on line 19. The dangerous operation is passing a user-influenced command string to the shell for execution.
6. Step 5 / Framework or library protections: No framework or library protection is visible. PHP `shell_exec()` does not automatically parameterize or escape command arguments.
7. Step 6 / Required privilege or authentication: The visible condition is only `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible, so the provided code indicates any requester able to submit the expected POST/request parameters can reach the path.
8. Step 7 / Security impact: If an attacker controls `$_REQUEST['ip']`, they can influence the OS command executed by `shell_exec()`. The impact is command injection / remote code execution as the PHP/web-server process user.
9. Step 8 / Weakest link: The weakest link is the incomplete blacklist on lines 8-14 combined with direct concatenation into `shell_exec()` on line 19. The defense is not complete because it removes only two tokens and leaves the command argument unvalidated and unescaped.
