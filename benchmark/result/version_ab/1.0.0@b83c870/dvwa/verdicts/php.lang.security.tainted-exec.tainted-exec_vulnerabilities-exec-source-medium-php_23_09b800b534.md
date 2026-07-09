# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present at vulnerabilities/exec/source/medium.php:23 and exactly reads `$cmd = shell_exec( 'ping  -c 4 ' . $target );`, which is a shell execution sink using a non-constant command containing request-controlled data. The only visible defense is an insufficient blacklist removing `&&` and `;`, so an exploitable command-injection path remains.

## Data flow

source: user-controlled `$_REQUEST['ip']` at vulnerabilities/exec/source/medium.php:5 → assignment to `$target` at line 5 → partial blacklist definitions at lines 8-11 → transformation via `str_replace()` at line 14 removing only `&&` and `;` → sink: command concatenation and execution in `$cmd = shell_exec( 'ping  -c 4 ' . $target );` at line 23 → output appended to `$html` at line 27

## Answers

1. Step 1: The dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` assigned to `$target` at `vulnerabilities/exec/source/medium.php:5`. The new `global:$html` context is unavailable and does not change this source analysis.
2. Step 2: Data flow: `$_REQUEST['ip']` is assigned to `$target` on line 5 → `$substitutions` blacklist is defined on lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → on the non-Windows branch, `$target` is concatenated into the shell command on line 23 → command output is later appended into `$html` on line 27. The additional `global:$html` context is unavailable and does not add any visible validation or alter the command-execution flow.
3. Step 3: The only visible sanitization is the blacklist on lines 8-14, which removes only `&&` and `;`. This is insufficient for command injection because other shell metacharacters and constructs remain possible, including `|`, backticks, `$()`, newline characters, redirection, and other shell syntax. No `escapeshellarg()`, `escapeshellcmd()`, strict IP address validation, or safe command API is visible.
4. Step 4: The sink is the flagged line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The unsafe operation is executing a shell command constructed by concatenating user-controlled `$target` into a command string.
5. Step 5: No framework or library automatic protection is visible in the provided code or the additional context. PHP `shell_exec()` does not automatically escape or parameterize command arguments.
6. Step 6: The authentication or privilege level required to trigger this code path is not visible in the provided context. The visible condition only checks `isset($_POST['Submit'])` on line 3; no authentication, authorization, or admin-only guard is shown.
7. Step 7: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection, potentially remote code execution as the PHP/web server process user. This may enable data theft, file modification, service disruption, or further compromise depending on process privileges.
8. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only two command separators but then passes the partially filtered request value directly into `shell_exec()` on line 23 without robust escaping or strict whitelist validation.
