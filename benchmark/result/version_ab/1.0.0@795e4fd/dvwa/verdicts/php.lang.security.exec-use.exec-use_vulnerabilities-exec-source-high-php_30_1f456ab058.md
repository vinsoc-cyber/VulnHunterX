# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and directly executes a non-constant shell command containing `$target`, which comes from `$_REQUEST['ip']`. The only visible defense is an incomplete blacklist, and no allowlist IP validation or shell argument escaping prevents command injection on the shown path.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (line 5) → `trim()` assigned to `$target` (line 5) → partial blacklist replacement via `$substitutions` and `str_replace(...)` (lines 8-21) → concatenation into shell command string (line 30) → `shell_exec()` command execution sink (line 30). Additional context `function:<unknown>` and `global:$html` was unavailable and adds no defensive step.

## Answers

1. Flagged line located: line 30 is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct reported by the rule is present on that line: `shell_exec()` executes a non-constant command built by concatenating `$target`. It lives in Function: `<unknown>` according to the provided context; the additional `function:<unknown>` context is unavailable and does not identify a more specific enclosing function.
2. Step 1: The dangerous data originates from HTTP request input at line 5: `$target = trim($_REQUEST[ 'ip' ]);`. The code path is gated by `isset($_POST['Submit'])` at line 3, but no authentication or upstream validation is visible.
3. Step 2: Data flow is `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` assigned to `$target` on line 5 → blacklist array defined on lines 8-18 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → `$target` concatenated into the command passed to `shell_exec()` on line 30.
4. Step 3: The only visible sanitization is blacklist replacement on lines 8-21. It removes selected strings/characters such as `||`, `&`, `;`, `| `, `-`, `$`, parentheses, and backticks. This is not sufficient for command injection because there is no strict IP-address allowlist validation and no `escapeshellarg()` or safe process API. For example, an internal newline is not removed by the blacklist and can act as a shell command separator.
5. Step 4: The sink is line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is execution of a shell command string containing request-derived data.
6. Step 5: No framework or library automatic protection is visible. The additional requested context for `function:<unknown>` and `global:$html` was unavailable, so it does not add any evidence of upstream validation, parameterization, or escaping. `shell_exec()` itself does not automatically escape command arguments.
7. Step 6: The visible trigger condition is only `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code or additional context, so the exact privilege level is not visible; an attacker able to send the relevant POST/request parameters to this code path can reach it.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the security impact is OS command injection, potentially remote code execution as the PHP/web server process user, with possible data theft, privilege escalation depending on host permissions, or denial of service.
9. Step 8: The weakest link is the blacklist sanitizer on lines 8-21. It is incomplete for shell command construction and is followed by direct concatenation into `shell_exec()` on line 30; no complete defense is visible.
