# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line executes a shell command constructed from user-controlled request data, and the only visible defense is an insufficient blacklist that removes just `&&` and `;`. The additional context was unavailable and does not alter the visible source-to-sink path or provide any specific defense that would prevent command injection.

## Data flow

HTTP request input `$_REQUEST['ip']` (line 5) → assigned to `$target` (line 5) → partial blacklist replacement via `str_replace()` removing only `&&` and `;` (lines 8-14) → concatenated into shell command string (line 19) → executed by `shell_exec()` (line 19). Additional requested context for `$_REQUEST`, `$html`, enclosing script, and callers was unavailable and revealed no extra defense.

## Answers

1. Step 0: The flagged line 19 is present and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. The rule-described construct is present on that line: `shell_exec()` executes a non-constant command built by concatenating `$target`.
2. Step 1: The dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. The additional context for `global:$_REQUEST` is unavailable and does not change this; in PHP, `$_REQUEST` is a superglobal populated from request parameters.
3. Step 2: Data flow: `$_REQUEST['ip']` is assigned to `$target` on line 5; blacklist substitutions are defined on lines 8-11; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; the transformed `$target` is concatenated into the command passed to `shell_exec()` on line 19 in the Windows branch. A similar non-Windows sink exists on line 23.
4. Step 3: The only visible sanitization is the blacklist on lines 8-14, which removes only `&&` and `;`. This is insufficient for command injection because it does not perform allowlist IP validation, does not use `escapeshellarg()`, and leaves other shell metacharacters or command/argument injection techniques available depending on shell and OS. The additional context does not show any upstream validation or sanitization.
5. Step 4: The sink is `shell_exec()` on line 19, where `$target` is concatenated into an OS command string: `'ping  ' . $target`. This is dangerous because the resulting command string is interpreted by the shell. The sibling sink at line 23 has the same issue for the non-Windows branch.
6. Step 5: No framework or library automatic protection is visible. The requested additional context for the enclosing script/route handler and callers was unavailable, and it does not reveal any automatic escaping, parameterization, allowlist validation, or access-control protection. `shell_exec()` itself does not provide command argument safety.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible in the original snippet or additional context, so based on the provided code the attacker only needs the ability to send a POST request with `Submit` set and control the `ip` request parameter.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the security impact is OS command injection, potentially arbitrary command execution under the PHP/web-server process privileges. This can lead to remote code execution, data theft, system compromise, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only two command separators before passing the value to `shell_exec()` on line 19, leaving no complete defense such as strict IP validation, shell argument escaping, or a non-shell execution API.
