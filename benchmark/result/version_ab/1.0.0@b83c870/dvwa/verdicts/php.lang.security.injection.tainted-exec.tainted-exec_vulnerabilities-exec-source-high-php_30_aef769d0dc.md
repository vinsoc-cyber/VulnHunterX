# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the analysis: the flagged line 30 is a real shell execution sink, and user-controlled `$_REQUEST['ip']` from line 5 reaches it after only incomplete blacklist filtering on line 21. Because no adequate validation, shell escaping, or upstream protection is visible, this is a clear OS command injection/RCE vulnerability.

## Data flow

vulnerabilities/exec/source/high.php:5 `$_REQUEST['ip']` → line 5 `trim($_REQUEST['ip'])` assigned to `$target` → lines 8-18 blacklist substitutions defined → line 21 `str_replace(array_keys($substitutions), $substitutions, $target)` reapplies `$target` with incomplete blacklist filtering → line 30 `$target` concatenated into `shell_exec('ping  -c 4 ' . $target)`

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 30 and is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a shell command string that includes concatenated variable data. The function is identified in the prompt as `<unknown>`; the code appears to be top-level PHP script code in `vulnerabilities/exec/source/high.php`.
2. Step 1: The dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` on line 5. The additional context for `global:$_REQUEST` is unavailable and does not change this; in PHP, `$_REQUEST` is a request superglobal populated from request parameters depending on configuration.
3. Step 2: The data flow is: `$_REQUEST['ip']` on line 5 → passed to `trim()` and assigned to `$target` on line 5 → blacklist substitutions are defined on lines 8-18 → `$target` is reassigned through `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → `$target` is concatenated into the command string passed to `shell_exec()` on line 30.
4. Step 3: The visible validation/sanitization consists of `trim()` on line 5 and blacklist removal via `str_replace()` on line 21 using the blacklist entries on lines 8-18. This is insufficient for command injection because it is not strict allowlist validation of an IP address and does not use `escapeshellarg()` or equivalent shell-argument escaping. The blacklist omits dangerous command-separation possibilities such as newlines, and blacklist filtering is generally bypass-prone for shell contexts.
5. Step 4: The sink is line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The unsafe operation is executing a shell command via `shell_exec()` using a command string constructed by concatenating user-controlled `$target`.
6. Step 5: No framework or library automatic protection is visible. `shell_exec()` does not automatically escape shell arguments. The additional context for `global:$html` and `global:$_REQUEST` is unavailable and provides no visible defense, validator, ORM parameterization, template auto-escaping, or shell escaping.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code. Based on the visible context, an attacker who can submit a POST parameter named `Submit` and control `$_REQUEST['ip']` can reach the sink; no admin-only or authenticated-only restriction is shown.
8. Step 7: The concrete security impact is OS command injection, potentially remote code execution as the PHP/web-server process. The command output is stored in `$cmd` on line 30 and then reflected into `$html` on line 34.
9. Step 8: The weakest link is the incomplete blacklist-based filtering on lines 8-21 before direct shell execution on line 30. No complete defense is visible: there is no strict IP validation, no argument escaping, and no safe process execution API that avoids the shell.
