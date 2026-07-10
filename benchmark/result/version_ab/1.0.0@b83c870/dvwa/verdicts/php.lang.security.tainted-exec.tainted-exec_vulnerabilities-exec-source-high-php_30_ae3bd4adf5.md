# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not change the analysis. The flagged sink at line 30 clearly executes a shell command containing request-controlled data from line 5, and the visible blacklist on lines 8-21 is demonstrably incomplete for command injection, leaving exploitable shell metacharacters such as a lone pipe.

## Data flow

vulnerabilities/exec/source/high.php: `$_REQUEST['ip']` user input (line 5) → `trim()` into `$target` (line 5) → blacklist array defined (lines 8-18) → `str_replace(...)` blacklist transformation of `$target` (line 21) → non-Windows branch (lines 28-30) → `$target` concatenated into `shell_exec('ping  -c 4 ' . $target)` (line 30)

## Answers

1. Step 0 / Flagged line location: The flagged line is present at line 30 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present: `shell_exec()` executes a non-constant command string built by concatenating `$target`. The provided context labels the function as `<unknown>`; it appears to be top-level PHP script code or an unknown enclosing scope.
2. Step 1 / Source: The dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` on line 5. The code path is entered when `$_POST['Submit']` is set on line 3.
3. Step 2 / Data trace: `$_REQUEST['ip']` is read on line 5, passed through `trim()`, and assigned to `$target`. A blacklist array is defined on lines 8-18. `$target` is then transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21. In the non-Windows branch, `$target` is concatenated into the command string on line 30 and executed by `shell_exec()`.
4. Step 3 / Validation, sanitization, or encoding: The only visible filtering is blacklist replacement on line 21 using the substitutions from lines 8-18. This is not sufficient for shell command injection. It removes some metacharacters such as `&`, `;`, `$`, parentheses, backticks, and `-`, but it does not perform strict IP validation and does not use `escapeshellarg()`. It also does not remove a lone pipe character unless followed by a space, so input such as `127.0.0.1|id` can still reach the shell as command syntax.
5. Step 4 / Sink: The sink is line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is passing a request-derived string to `shell_exec()`, causing it to be interpreted by the operating system shell.
6. Step 5 / Framework or library protections: No framework, middleware, ORM, template auto-escaping, or shell-escaping protection is visible. The additional requested context for `global:$html` and `global:$_REQUEST` was unavailable and does not show any new protection. PHP `shell_exec()` does not automatically quote or sanitize arguments.
7. Step 6 / Required privilege or authentication: The only visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication, authorization, role check, or admin-only guard is visible in the provided context. Based on the shown code, any requester able to submit the relevant POST/request parameters can trigger the path.
8. Step 7 / Security impact: The impact is remote command execution in the context of the web server/PHP process. For example, because line 21 does not remove a lone `|`, an attacker-controlled `ip` value can inject a pipeline into the command executed at line 30.
9. Step 8 / Weakest link: The weakest link is the blacklist-based defense on lines 8-21. It is incomplete and brittle for shell command construction; the command is still assembled by string concatenation at line 30 instead of using strict allowlist validation for an IP address and safe shell argument escaping such as `escapeshellarg()`.
