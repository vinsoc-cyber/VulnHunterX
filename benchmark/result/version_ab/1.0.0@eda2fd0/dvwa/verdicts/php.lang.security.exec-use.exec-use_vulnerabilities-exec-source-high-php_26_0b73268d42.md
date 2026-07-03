# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged construct is present: line 26 executes a non-constant shell command built from request-controlled `$target`. The only visible defenses are `trim()` and an incomplete blacklist, with no strict IP validation or shell escaping before `shell_exec()`, so an exploitable command-injection path is clearly present.

## Data flow

HTTP request source `$_REQUEST['ip']` (vulnerabilities/exec/source/high.php:5) → `trim()` assignment to `$target` (line 5) → blacklist replacement via `str_replace(...)` (line 21, using substitutions from lines 8-18) → OS branch via `php_uname('s')` (line 24) → shell command execution at `shell_exec('ping  ' . $target)` (line 26, flagged line) or `shell_exec('ping  -c 4 ' . $target)` (line 30). Additional context for `global:$html` is unavailable and does not add any sanitization before the sink.

## Answers

1. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` at `vulnerabilities/exec/source/high.php:5`. The code path is gated by `isset($_POST['Submit'])` at line 3, which is also request-controlled. The additional `global:$html` context is unavailable and does not change the source analysis.
2. Step 2: Data flow is `$_REQUEST['ip']` at line 5 → `trim($_REQUEST['ip'])` assigned to `$target` at line 5 → blacklist array defined at lines 8-18 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` at line 21 → OS check at line 24 → concatenated into `shell_exec('ping  ' . $target)` at line 26 on Windows, or `shell_exec('ping  -c 4 ' . $target)` at line 30 on Unix-like systems.
3. Step 3: The visible transformations are `trim()` at line 5 and blacklist replacement at line 21. `trim()` only removes leading/trailing whitespace. The blacklist removes some shell metacharacters such as `&`, `;`, `$`, parentheses, backticks, and `-` at lines 8-18, but it is not sufficient command-injection protection because there is no strict IP-address allowlist and no `escapeshellarg()` or equivalent shell-argument escaping. For example, embedded control characters such as a newline are not visibly removed by the blacklist.
4. Step 4: The sink is `shell_exec()` at line 26, the exact flagged line: `$cmd = shell_exec( 'ping  ' . $target );`. The alternate sink is also `shell_exec()` at line 30. The unsafe operation is executing a shell command constructed by string concatenation with request-controlled data.
5. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not parameterize or automatically escape shell arguments. The additional `global:$html` context is unavailable and provides no visible protection for the command-execution sink.
6. Step 6: Authentication or authorization requirements are not visible in the provided context. The only visible trigger condition is that a request sets `$_POST['Submit']` at line 3 and supplies `$_REQUEST['ip']` at line 5, so no authentication requirement can be confirmed from the snippet.
7. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection / remote code execution as the PHP/web-server process. The command output is stored in `$cmd` at line 26 or line 30 and then included in `$html` at line 34.
8. Step 8: The weakest link is the blacklist-based filtering at lines 8-21 before direct shell execution at lines 26 and 30. The defense is incomplete because it attempts to remove selected characters rather than enforcing a strict valid-IP format or passing the user input through `escapeshellarg()`.
