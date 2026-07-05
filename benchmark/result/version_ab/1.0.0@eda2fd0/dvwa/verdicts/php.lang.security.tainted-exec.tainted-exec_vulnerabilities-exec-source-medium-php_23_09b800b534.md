# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the analysis: user-controlled `$_REQUEST['ip']` flows through only an inadequate blacklist before reaching `shell_exec()` at the flagged line. Because no adequate escaping, allowlist validation, or framework protection is visible, the reported tainted command execution issue is clearly present.

## Data flow

user-controlled `$_REQUEST['ip']` (`vulnerabilities/exec/source/medium.php:5`; requested `global:_REQUEST` context unavailable) → `$target` assignment (`vulnerabilities/exec/source/medium.php:5`) → partial blacklist substitution removing only `&&` and `;` (`vulnerabilities/exec/source/medium.php:8-14`) → command string concatenation and execution by `shell_exec()` on Windows (`vulnerabilities/exec/source/medium.php:20`) or at the exact flagged non-Windows sink `$cmd = shell_exec( 'ping  -c 4 ' . $target );` (`vulnerabilities/exec/source/medium.php:23`)

## Answers

1. Step 1: The potentially dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` assigned to `$target` in `vulnerabilities/exec/source/medium.php:5`. The additional context for `global:_REQUEST` is unavailable and does not show any constraint or sanitization.
2. Step 2: Data flow: `$_REQUEST['ip']` source at `vulnerabilities/exec/source/medium.php:5` → assigned to `$target` at line 5 → blacklist substitutions defined at lines 8-11 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` at line 14 → concatenated into shell command in `shell_exec('ping  ' . $target)` at line 20 on Windows or `shell_exec('ping  -c 4 ' . $target)` at the flagged line 23 on non-Windows systems.
3. Step 3: The only visible sanitization is blacklist replacement at `vulnerabilities/exec/source/medium.php:14`, removing only `&&` and `;` as configured on lines 8-11. This is not sufficient for command injection because other shell metacharacters and command substitution mechanisms remain available, such as `|`, single `&`, backticks, `$()`, newline characters, and redirection. No `escapeshellarg()`, `escapeshellcmd()`, or strict IP address allowlist validation is visible. The additional requested global context is unavailable and does not provide a defense.
4. Step 4: The sink is `shell_exec()` at `vulnerabilities/exec/source/medium.php:20` and the exact flagged line `vulnerabilities/exec/source/medium.php:23`: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is executing a non-constant shell command containing user-controlled data.
5. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically escape command arguments. The additional `global:_REQUEST` and `global:_POST` context is unavailable and shows no automatic protection or upstream validation.
6. Step 6: Authentication state is not visible in the provided context. The visible reachability condition is only `isset($_POST['Submit'])` at `vulnerabilities/exec/source/medium.php:3`; the `global:_POST` context is unavailable and does not establish any authentication or authorization restriction.
7. Step 7: If an attacker can submit the visible request parameters, the impact is command injection leading to arbitrary OS command execution as the PHP/web server process, via `shell_exec()` at line 20 or line 23.
8. Step 8: The weakest link is the incomplete blacklist at lines 8-14. It attempts to remove only `&&` and `;`, but leaves many shell injection primitives intact before directly concatenating `$target` into `shell_exec()` at lines 20 and 23.
