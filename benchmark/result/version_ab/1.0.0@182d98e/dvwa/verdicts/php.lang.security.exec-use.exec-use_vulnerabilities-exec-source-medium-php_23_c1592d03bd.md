# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged sink is visible at line 23 inside the shown `<unknown>`/top-level PHP context, and request input from line 5 reaches `shell_exec()` after only an insufficient blacklist. Additional caller context is not necessary to establish the command-injection vulnerability on this flagged path.

## Data flow

user-controlled `$_REQUEST['ip']` at vulnerabilities/exec/source/medium.php:5 → assigned to `$target` at line 5 → partial blacklist replacement via `str_replace()` at lines 8-14 → concatenated into shell command at line 23 → executed by `shell_exec()` at line 23

## Answers

1. Step 0 / Flagged line located: Line 23 is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: a non-constant command string is passed to `shell_exec()`. The snippet identifies the function as `<unknown>`; this appears to be top-level PHP script code rather than a named function.
2. Step 1 / Source: The potentially dangerous data originates from user-controlled request input at line 5: `$target = $_REQUEST['ip'];`. The code path is gated by `isset($_POST['Submit'])` on line 3.
3. Step 2 / Data trace: `$_REQUEST['ip']` flows into `$target` on line 5. A blacklist array is defined on lines 8-11. `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14. The resulting `$target` is concatenated into the command passed to `shell_exec()` on line 23.
4. Step 3 / Validation or sanitization: Lines 8-14 remove only `&&` and `;`. This is not sufficient for shell command injection prevention because other shell metacharacters and command-substitution forms remain possible, such as `|`, single `&`, backticks, `$()`, redirection, newline separators, or argument injection. No allowlist IP validation and no `escapeshellarg()`/`escapeshellcmd()` is visible.
5. Step 4 / Sink: The sink is line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is executing a shell command constructed by concatenating user-controlled data.
6. Step 5 / Framework/library protection: No automatic framework or library protection is visible. PHP `shell_exec()` does not parameterize or safely separate command arguments; it executes a shell command string.
7. Step 6 / Required privilege/authentication: The only visible requirement is that `$_POST['Submit']` be set on line 3. No authentication or authorization guard is visible in the provided code.
8. Step 7 / Security impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell syntax into the command on line 23, potentially causing remote command execution as the PHP/web server process user.
9. Step 8 / Weakest link: The weakest link is the incomplete blacklist on lines 8-14 combined with direct concatenation into `shell_exec()` on line 23. The defense is incomplete because it is not an allowlist and does not escape the command argument safely.
