# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not reveal any specific upstream defense. In the visible code, attacker-controlled request input reaches `shell_exec()` on the exact flagged line after only incomplete blacklist filtering and without shell-safe escaping, so the reported tainted command execution vulnerability is clearly present.

## Data flow

HTTP request input `$_REQUEST['ip']` (line 5) → `trim()` assigned to `$target` (line 5) → blacklist `str_replace()` using substitutions from lines 8-18 reassigned to `$target` (line 21) → OS check branch via `stristr(php_uname('s'), 'Windows NT')` (line 24) → concatenation into `shell_exec('ping  ' . $target)` (line 26)

## Answers

1. Step 0 / flagged line: The flagged line is present at line 26 and is exactly `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: a non-constant command string is executed via `shell_exec()` after concatenating `$target`.
2. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` is read on line 5 and assigned to `$target` after `trim()`. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not change this.
3. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` assigned to `$target` on line 5 → `$target` is passed through `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigned on line 21 → `$target` is concatenated into the command string passed to `shell_exec()` on line 26 in the Windows branch. A sibling non-Windows sink also exists on line 30, but the flagged line is line 26.
4. Step 3: The visible transformations are `trim()` on line 5 and blacklist replacement using `$substitutions` from lines 8-18 applied by `str_replace()` on line 21. This is not sufficient for command injection because there is no allowlist validation that the input is a valid IP address and no `escapeshellarg()` or equivalent shell-safe argument quoting before `shell_exec()`.
5. Step 4: The sink is `shell_exec('ping  ' . $target)` on line 26. The dangerous operation is execution of an OS shell command constructed by concatenating attacker-controlled request data into the command string.
6. Step 5: No framework or library automatic protection is visible. The additional requested route/bootstrap/enclosing-handler context is unavailable, and the shown PHP built-in `shell_exec()` does not automatically parameterize or safely quote shell arguments.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization requirement is visible in the provided context; therefore, based only on the shown code, an attacker needs the ability to send a request with `Submit` set and control the `ip` parameter.
8. Step 7: The concrete security impact is OS command injection, potentially remote code execution as the user running the PHP/web server process.
9. Step 8: The weakest link is the blacklist-based filtering on lines 8-21. It attempts to remove selected metacharacters but does not provide complete command-argument safety; the complete defense would be strict IP validation plus safe shell argument escaping or avoiding shell execution with untrusted input.
