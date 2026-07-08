# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not reveal any additional defense. In the visible code, attacker-controlled request data flows into `shell_exec()` after only incomplete blacklist filtering, with no `escapeshellarg()` or strict IP validation, making the command-injection finding real.

## Data flow

HTTP request input `$_REQUEST['ip']` at vulnerabilities/exec/source/high.php:5 → `trim()` assigned to `$target` at line 5 → blacklist replacement via `str_replace()` at line 21 using substitutions from lines 8-18 → concatenated into non-constant shell command in `shell_exec('ping  -c 4 ' . $target)` at line 30 → command output appended to `$html` at line 34

## Answers

1. Step 0 / flagged line: The exact flagged line is line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule construct is present on that line: `shell_exec()` is called with a non-constant command string built by concatenating `$target`. The enclosing function is reported as `<unknown>`; the visible code appears to be top-level PHP script code, but no named function is shown.
2. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` on line 5. `$_REQUEST` is a PHP superglobal containing user-controllable request parameters. The additional context for `global:$_REQUEST` is unavailable and does not add any visible protection.
3. Step 2: The data flow is: `$_REQUEST['ip']` is read and passed through `trim()` into `$target` on line 5; a blacklist array is defined on lines 8-18; `$target` is modified by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21; in the non-Windows branch, `$target` is concatenated into the command string passed to `shell_exec()` on line 30.
4. Step 3: The only visible sanitization is blacklist replacement on line 21 using substitutions from lines 8-18. It removes some shell metacharacters/sequences, including `||`, `&`, `;`, `| `, `-`, `$`, `(`, `)`, and backticks. This is insufficient for command injection because it is not strict IP validation, does not use `escapeshellarg()`, and leaves shell-relevant separators/metacharacters such as newlines and a bare pipe not followed by a space.
5. Step 4: The sink is `shell_exec()` on line 30. The dangerous operation is executing a shell command constructed by concatenating attacker-controlled `$target` into `'ping  -c 4 ' . $target`.
6. Step 5: No framework or library automatic protection is visible. The additional requested contexts for globals/callers are unavailable and do not show any configured protection. PHP `shell_exec()` does not automatically escape concatenated arguments.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is shown in the provided context, so the required privilege level is not visible; based on the visible code, any requester able to submit the expected POST parameter could reach the path.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection, potentially remote code execution as the PHP/web server process. The command output is stored in `$cmd` on line 30 and then included in `$html` on line 34.
9. Step 8: The weakest link is relying on incomplete blacklist filtering at line 21 before direct shell execution at line 30. The defense is incomplete because it neither validates `$target` as a legitimate IP address nor escapes it with `escapeshellarg()` before passing it to the shell.
