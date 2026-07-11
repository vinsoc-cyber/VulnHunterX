# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not add any visible defense or change the prior analysis. The flagged line executes a shell command containing request-controlled input after only incomplete blacklist filtering, leaving an exploitable command-injection path such as newline-based command separation.

## Data flow

`vulnerabilities/exec/source/high.php:5` user input `$_REQUEST['ip']` → `vulnerabilities/exec/source/high.php:5` `trim()` assigned to `$target` → `vulnerabilities/exec/source/high.php:21` blacklist `str_replace()` assigned back to `$target` → `vulnerabilities/exec/source/high.php:30` `$target` concatenated into `'ping  -c 4 ' . $target` → `vulnerabilities/exec/source/high.php:30` `shell_exec()` command execution sink

## Answers

1. Step 0: The flagged line is line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant shell command formed by concatenating `$target`.
2. Step 1: The potentially dangerous data originates from user-controlled request input: `$_REQUEST['ip']` on line 5. The additional context for `global:$_REQUEST` is unavailable and does not show any upstream validation or normalization.
3. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` assigned to `$target` on line 5 → blacklist array defined on lines 8-18 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → on the non-Windows branch, `$target` is concatenated into the command string on line 30 → passed to `shell_exec()` on line 30. The additional context for `$html` is unavailable and does not change this source-to-sink path.
4. Step 3: There is blacklist-based filtering on lines 8-21. It removes some characters/sequences such as `||`, `&`, `;`, `| `, `-`, `$`, parentheses, and backticks. This is insufficient for shell command injection because it does not strictly validate the value as an IP address, does not use `escapeshellarg()`, and leaves shell syntax such as newlines available as command separators.
5. Step 4: The sink is `shell_exec()` on line 30. The dangerous operation is executing a shell command string containing user-controlled `$target`.
6. Step 5: No framework or library protection is visible. `shell_exec()` does not automatically parameterize or safely escape shell arguments. The additional requested global contexts are unavailable and provide no visible defense.
7. Step 6: The visible trigger is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code. Therefore, based only on visible context, any requester able to submit this POST parameter and an `ip` request parameter can reach the code.
8. Step 7: The concrete security impact is OS command injection, potentially remote code execution as the PHP/web server process. The resulting command output is placed into `$cmd` on line 30 and appended to `$html` on line 34.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-21. It attempts to remove selected metacharacters instead of applying strict IP validation or shell argument escaping before the user-controlled value reaches `shell_exec()` on line 30.
