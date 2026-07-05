# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 19 clearly executes a shell command built from user-controlled request input from line 5. The only visible defense is an incomplete blacklist on lines 8-14, and the additional context did not reveal any upstream validation or framework protection that would prevent command injection.

## Data flow

HTTP request input `$_REQUEST['ip']` at vulnerabilities/exec/source/medium.php:5 → assigned to `$target` at line 5 → partial blacklist replacement using `$substitutions` defined at lines 8-11 and `str_replace()` at line 14 → OS branch at lines 17-19 → concatenated into `shell_exec('ping  ' . $target)` at line 19

## Answers

1. Step 0 / flagged line location: The flagged line 19 is present and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. This line contains the construct described by the rule: a non-constant shell command is executed via `shell_exec()` after concatenating `$target` into the command string.
2. Function location: The provided context identifies the function as `<unknown>`. The code appears to be top-level PHP script code in `vulnerabilities/exec/source/medium.php`, not inside a visible named function or method.
3. Additional context impact: The newly provided context does not change the prior analysis. `global:$_REQUEST`, `global:$html`, and the enclosing script/router context are unavailable/out-of-snippet, so no additional upstream validation, authentication, routing, or framework protection is visible.
4. Step 1: The potentially dangerous data originates from HTTP request input. On line 5, `$target = $_REQUEST['ip'];` reads the `ip` parameter from `$_REQUEST`, which can include user-controlled GET, POST, or cookie input depending on PHP configuration.
5. Step 2: The data flow is: `$_REQUEST['ip']` on line 5 → assigned to `$target` on line 5 → `$target` passed through `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → resulting `$target` concatenated into a shell command at line 19 in the Windows branch. The same sanitized `$target` is also used in the non-Windows `shell_exec()` sink on line 23, though the reported flagged line is line 19.
6. Step 3: A blacklist transformation is applied. Lines 8-11 define `$substitutions` to remove only `&&` and `;`, and line 14 applies that replacement. This is not sufficient for command-injection prevention because many shell metacharacters and command separators remain possible depending on OS/shell, such as `&`, `|`, newline characters, redirection operators, backticks, `$()`, or other shell-specific syntax. No strict IP allowlist validation and no `escapeshellarg()`/`escapeshellcmd()` call is visible.
7. Step 4: The sink is `shell_exec()` at line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is execution of a shell command string containing attacker-influenced data. Because the input is concatenated directly into the command, shell metacharacters in `$target` can alter the command executed.
8. Step 5: No framework or library protection is visible. PHP `shell_exec()` does not provide automatic argument separation or escaping. The additional requested context was unavailable, so there is no visible evidence of upstream framework filtering, middleware validation, ORM-style parameterization, or template auto-escaping relevant to this command-execution sink.
9. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code or additional context. Based on the visible code, an attacker needs the ability to send an HTTP request with `Submit` set and an `ip` parameter.
10. Step 7: If an attacker controls `ip`, the security impact is command injection leading to remote code execution as the PHP/web-server process user. Depending on server privileges, this can enable data theft, modification of server-side files, lateral movement, privilege escalation attempts, or denial of service.
11. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only `&&` and `;`, but does not enforce that `$target` is a valid IP address and does not safely escape or separate shell arguments before the `shell_exec()` sink on line 19. No complete defense is visible.
