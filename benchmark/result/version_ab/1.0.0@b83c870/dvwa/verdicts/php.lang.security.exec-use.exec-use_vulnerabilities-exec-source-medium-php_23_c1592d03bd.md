# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is visible and directly executes a command string containing request-controlled data. The only visible defense is an incomplete blacklist, which does not adequately prevent shell command injection.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` → vulnerabilities/exec/source/medium.php:5 `$target` → vulnerabilities/exec/source/medium.php:14 `str_replace()` blacklist removing only `&&` and `;` → vulnerabilities/exec/source/medium.php:23 concatenation into `'ping  -c 4 ' . $target` → vulnerabilities/exec/source/medium.php:23 `shell_exec()`

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/medium.php:23 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command string built by concatenating `$target`.
2. Function location: The snippet identifies the function as `<unknown>`; this appears to be top-level PHP code gated by `if( isset( $_POST[ 'Submit' ]  ) )` at line 3, not a named function in the provided context.
3. Source: The dangerous data originates from request-controlled input at vulnerabilities/exec/source/medium.php:5: `$target = $_REQUEST[ 'ip' ];`.
4. Trace: `$_REQUEST['ip']` is assigned to `$target` on line 5; `$substitutions` is defined on lines 8-11 to remove only `&&` and `;`; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; on the non-Windows branch, `$target` is concatenated into a shell command at line 23 and passed to `shell_exec()`.
5. Validation/sanitization: The only visible sanitization is a blacklist on lines 8-14 removing `&&` and `;`. This is insufficient for command injection because it does not enforce an IP-address allowlist and does not use shell-safe escaping such as `escapeshellarg()`; other shell syntax such as `|`, `$()`, backticks, newlines, redirection, or argument-level abuse is not visibly prevented.
6. Sink: The sink is vulnerabilities/exec/source/medium.php:23, `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is shell command execution with user-controlled data embedded in the command string.
7. Framework/library protections: No framework protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments.
8. Reachability/privilege: The path is reachable if `isset($_POST['Submit'])` is true at line 3 and the OS branch reaches the non-Windows case at lines 21-24. No authentication or authorization check is visible in the provided code.
9. Impact: Successful exploitation would be OS command injection, potentially remote code execution as the web server/PHP process user.
10. Weakest link: The weakest link is the incomplete blacklist at lines 8-14 combined with direct concatenation into `shell_exec()` at line 23.
