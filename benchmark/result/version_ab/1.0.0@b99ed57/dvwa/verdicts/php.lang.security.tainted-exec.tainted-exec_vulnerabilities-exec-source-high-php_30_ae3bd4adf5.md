# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not add any visible defense. The flagged sink at line 30 executes a shell command containing request-controlled data from line 5, and the only visible sanitization is an incomplete blacklist on lines 8-21 rather than strict validation or shell escaping.

## Data flow

`$_REQUEST['ip']` in `vulnerabilities/exec/source/high.php` line 5 → `trim()` assigned to `$target` line 5 → blacklist substitutions defined lines 8-18 → blacklist applied by `str_replace()` line 21 → non-Windows branch selected lines 28-30 → `$target` concatenated into `'ping  -c 4 '` line 30 → executed by `shell_exec()` line 30

## Answers

1. Step 0 / flagged line: The flagged line is present at line 30 and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the rule-described construct: a non-constant shell command is built by concatenating `$target` into a `shell_exec()` call. The function is labeled `<unknown>` in the provided context and appears to be top-level PHP script code.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` on line 5. The additional context for `global:$_REQUEST` is unavailable and does not show any constraint or trusted assignment that would change this.
3. Step 2: The data flow is: `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` assigned to `$target` on line 5 → `$target` passed through `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → `$target` concatenated into the command string on line 30 → executed by `shell_exec()` on line 30.
4. Step 3: A blacklist is defined on lines 8-18 and applied on line 21. This is not sufficient shell-command sanitization. It removes selected strings/characters such as `||`, `&`, `;`, `| `, `-`, `$`, parentheses, and backticks, but it does not perform strict IP validation and does not use `escapeshellarg()`. Shell control characters such as newlines, and potentially pipe syntax not matching `| `, are not adequately handled.
5. Step 4: The sink is `shell_exec()` at line 30. The dangerous operation is execution of a shell command constructed as `'ping  -c 4 ' . $target`, where `$target` is derived from request input.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically escape or parameterize shell arguments. The additional global contexts for `$_REQUEST` and `$html` are unavailable and provide no visible protection.
7. Step 6: The required authentication or privilege level is not visible in the provided context. The only visible reachability condition is `isset($_POST['Submit'])` on line 3. No authentication, authorization, or admin-only check is shown.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command execution under the privileges of the PHP/web server process. This can lead to remote code execution, data theft, service disruption, or broader host compromise depending on process permissions.
9. Step 8: The weakest link is the blacklist-based filtering on lines 8-21 before passing data to `shell_exec()` on line 30. The defense is incomplete because it does not enforce a safe IP-address whitelist and does not shell-escape the argument with `escapeshellarg()`.
