# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and executes a shell command containing `$target`, which is directly sourced from `$_REQUEST['ip']` with no visible sanitization or escaping. Although caller/routing context could clarify authentication requirements, the exploitability of the flagged sink itself is clear from the provided code.

## Data flow

vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → `$target` → vulnerabilities/exec/source/low.php:14 string concatenation `'ping  -c 4 ' . $target` → vulnerabilities/exec/source/low.php:14 `shell_exec()`

## Answers

1. Flagged line location: line 14 in `vulnerabilities/exec/source/low.php` is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present: a non-constant command string is built using `$target` and executed via `shell_exec()`.
2. Function location: The snippet is not inside a named PHP function; the provided context labels it as `Function: <unknown>`, and the code appears to execute at top level when the file is included or requested.
3. Q1: The potentially dangerous data originates from user-controlled HTTP request input on line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` may contain GET, POST, and cookie data depending on PHP configuration.
4. Q2: Data flow chain with file/line references: `vulnerabilities/exec/source/low.php:3` checks only whether `$_POST['Submit']` is set; `vulnerabilities/exec/source/low.php:5` assigns `$_REQUEST['ip']` to `$target`; `vulnerabilities/exec/source/low.php:14` concatenates `$target` into `'ping  -c 4 ' . $target`; `vulnerabilities/exec/source/low.php:14` passes that string to `shell_exec()`.
5. Q3: No validation, sanitization, escaping, allowlist, or type enforcement is visible between source line 5 and sink line 14. Specifically, there is no `escapeshellarg()`, `escapeshellcmd()`, IP address validation, or strict allowlist before `shell_exec()`.
6. Q4: The sink is `shell_exec()` at `vulnerabilities/exec/source/low.php:14`. The unsafe operation is invoking the operating-system shell with a command string containing untrusted input, which can allow shell metacharacter injection.
7. Q5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically escape arguments or parameterize shell commands.
8. Q6: The only visible reachability condition is `isset($_POST['Submit'])` at line 3. No authentication or authorization check is visible in the provided code. Additional routing/auth context could clarify required privilege, but it is not necessary to establish the command-injection issue on this path.
9. Q7: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection / remote command execution as the PHP web-server user. For example, shell metacharacters could append arbitrary commands to the intended `ping` command.
10. Q8: The weakest link is the direct concatenation of untrusted request data into a shell command at line 14 after assignment from `$_REQUEST['ip']` at line 5, with no visible validation or escaping.
