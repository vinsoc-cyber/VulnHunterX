# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink at line 23 executes a shell command containing `$target`, which comes from attacker-controlled `$_REQUEST['ip']` at line 5. The only visible defense is an insufficient blacklist removing `&&` and `;` on lines 8-14, leaving exploitable command-injection vectors before `shell_exec()`.

## Data flow

source `$_REQUEST['ip']` (line 5) → assigned to `$target` (line 5) → blacklist definitions for `&&` and `;` (lines 8-11) → partial sanitization via `str_replace()` (line 14) → concatenation into command string `'ping  -c 4 ' . $target` (line 23) → execution by `shell_exec()` sink (line 23). Additional context `global:$_REQUEST` and `function:<unknown>` was unavailable and adds no visible defense.

## Answers

1. Step 0 / flagged line location: The flagged line is line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command built by concatenating `$target`.
2. Step 1: The potentially dangerous data originates from user-controlled request input at line 5: `$target = $_REQUEST[ 'ip' ];`. The additional context for `global:$_REQUEST` is unavailable and does not change this; in PHP, `$_REQUEST` is a request superglobal populated from attacker-controllable request data depending on configuration.
3. Step 2: Data flow: `$_REQUEST['ip']` is assigned to `$target` on line 5; blacklist entries are defined on lines 8-11; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; the transformed `$target` is concatenated into the shell command on line 23; the resulting command is executed by `shell_exec()` on line 23.
4. Step 3: A blacklist-style transformation is applied on lines 8-14. It removes only `&&` and `;`. This is insufficient for OS command injection because other shell metacharacters and command-substitution mechanisms remain possible, such as `|`, single `&`, backticks, `$()`, newlines, redirection, and other shell parsing behavior. No strict IP address validation, allowlist, `escapeshellarg()`, or safe process API is visible.
5. Step 4: The sink is `shell_exec()` at line 23. The dangerous operation is passing an attacker-influenced string to the system shell after concatenating it into `ping  -c 4 `.
6. Step 5: No framework or library automatic protection is visible. The additional requested context was unavailable, and PHP `shell_exec()` does not automatically escape or parameterize shell arguments.
7. Step 6: The visible reachability condition is `isset($_POST['Submit'])` at line 3. No authentication or authorization check is visible in the provided code or additional context. Based on visible evidence, an attacker who can send a request with `Submit` and `ip` parameters can reach the vulnerable code path.
8. Step 7: The concrete security impact is OS command injection, potentially remote code execution as the web server/PHP process user. This can lead to data theft, service compromise, lateral movement depending on host permissions, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only two command separators but then still passes attacker-controlled data to `shell_exec()` on line 23 without robust escaping or strict allowlist validation.
