# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the visible flow: user-controlled `$_REQUEST['ip']` reaches `shell_exec()` on line 26 after only an incomplete blacklist. Because shell metacharacters such as a bare `|` can survive and no adequate escaping or allowlist validation is visible, the flagged sink is exploitable as command injection.

## Data flow

vulnerabilities/exec/source/high.php:5 `$_REQUEST['ip']` → `trim()` assignment to `$target` at line 5 → blacklist replacement via `str_replace(...)` at line 21 using substitutions from lines 8-18 → concatenation into command string in `shell_exec('ping  ' . $target)` at line 26

## Answers

1. Step 0 / flagged line location: The flagged line is line 26: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that exact line: `shell_exec()` executes a non-constant command string built by concatenating `$target`. The function is listed as `<unknown>`; the code appears in top-level PHP script context in `vulnerabilities/exec/source/high.php`.
2. Step 1: The dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` on line 5. The new context for `global:_REQUEST` and `global:_POST` is unavailable and does not change this.
3. Step 2: Data flow: `$_REQUEST['ip']` is read and passed through `trim()` into `$target` on line 5; blacklist substitutions are defined on lines 8-18; `$target` is modified by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21; the resulting `$target` is concatenated into the shell command passed to `shell_exec()` on line 26.
4. Step 3: A blacklist transformation is applied on line 21 using substitutions from lines 8-18. This is not sufficient for command injection because it is not strict IP validation and does not use `escapeshellarg()` or `escapeshellcmd()`. The blacklist is incomplete; for example, it removes `| ` but not a bare pipe `|`, so Windows shell syntax such as `127.0.0.1|whoami` can still alter command execution.
5. Step 4: The sink is `shell_exec()` on line 26. The dangerous operation is OS shell command execution using a string built from user-controlled `$target`: `'ping  ' . $target`.
6. Step 5: No framework or library automatic protection is visible. The additional requested context was unavailable, and PHP `shell_exec()` does not automatically escape or parameterize command arguments.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible, so based on the provided code, an attacker only needs the ability to send a request setting `Submit` and `ip`.
8. Step 7: The concrete security impact is OS command injection / remote command execution under the privileges of the PHP/web-server process. On the Windows branch at line 26, attacker-controlled shell metacharacters that survive the blacklist can execute additional commands.
9. Step 8: The weakest link is the blacklist sanitizer on line 21. It is incomplete and unsuitable for shell command construction; the defense would need strict allowlist validation of an IP address and/or proper shell argument escaping.
