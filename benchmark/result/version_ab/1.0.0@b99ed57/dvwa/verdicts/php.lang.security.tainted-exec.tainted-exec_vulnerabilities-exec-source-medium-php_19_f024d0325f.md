# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is visible and exact: line 19 executes a shell command containing user-controlled request data. The only visible defense is an incomplete blacklist on lines 8-14, which does not adequately prevent command injection before `shell_exec()`.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` → vulnerabilities/exec/source/medium.php:5 `$target` assignment → vulnerabilities/exec/source/medium.php:14 partial blacklist via `str_replace()` removing only `&&` and `;` → vulnerabilities/exec/source/medium.php:19 concatenation into `'ping  ' . $target` → vulnerabilities/exec/source/medium.php:19 `shell_exec()`

## Answers

1. Flagged line location: vulnerabilities/exec/source/medium.php:19 is exactly `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: a non-constant command string is passed to PHP `shell_exec()`.
2. Function/context: The code context labels the function as `<unknown>`. The snippet appears to be top-level PHP request-handling code rather than a named function or method. No enclosing named function is visible.
3. Source: The potentially dangerous data originates from HTTP request input at vulnerabilities/exec/source/medium.php:5: `$target = $_REQUEST[ 'ip' ];`.
4. Trace: `$_REQUEST['ip']` is assigned to `$target` at line 5; `$target` is passed through `str_replace(array_keys($substitutions), $substitutions, $target)` at line 14; the transformed `$target` is concatenated into a shell command at line 19; the resulting command is executed by `shell_exec()` at line 19.
5. Validation/sanitization: Lines 8-11 define a blacklist that removes only `&&` and `;`, and line 14 applies it. This is not sufficient command-injection protection because other shell metacharacters/operators remain possible, including `|`, redirection, newlines, and Windows-specific operators such as single `&`. No `escapeshellarg()`, `escapeshellcmd()`, or strict IP allowlist validation is visible.
6. Sink: The sink is vulnerabilities/exec/source/medium.php:19: `shell_exec()` executes a shell command constructed from user-controlled data. This is dangerous because PHP passes the command string to the shell.
7. Framework/library protection: No framework-level or library-level automatic protection is visible. PHP `shell_exec()` does not parameterize or safely escape command arguments automatically.
8. Reachability/privilege: The code path is gated by vulnerabilities/exec/source/medium.php:3: `if( isset( $_POST[ 'Submit' ]  ) )`. No authentication or authorization guard is visible. A requester able to submit a POST parameter named `Submit` and provide `ip` can reach the sink based on the provided code.
9. Impact: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection / remote command execution as the PHP web-server process.
10. Weakest link: The weakest link is the incomplete blacklist at lines 8-14 before direct shell execution at line 19. The defense is not complete because it does not robustly escape or strictly validate the shell argument.
