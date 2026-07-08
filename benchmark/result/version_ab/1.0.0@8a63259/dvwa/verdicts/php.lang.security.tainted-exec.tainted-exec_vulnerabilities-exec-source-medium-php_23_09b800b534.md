# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context for `$_REQUEST` and `$_POST` is unavailable and does not reveal any defense that changes the analysis. The visible code shows user-controlled request data reaching `shell_exec()` on line 23 after only an insufficient blacklist, with no adequate escaping or IP allowlist validation.

## Data flow

`vulnerabilities/exec/source/medium.php:3` request path gated by `isset($_POST['Submit'])` → `vulnerabilities/exec/source/medium.php:5` user-controlled `$_REQUEST['ip']` assigned to `$target` → `vulnerabilities/exec/source/medium.php:8-11` blacklist only defines removals for `&&` and `;` → `vulnerabilities/exec/source/medium.php:14` `$target` transformed with `str_replace()` and reassigned → `vulnerabilities/exec/source/medium.php:23` `$target` concatenated into `'ping  -c 4 ' . $target` → `vulnerabilities/exec/source/medium.php:23` command executed by `shell_exec()`

## Answers

1. Step 0 / Locate flagged line: The flagged line 23 is present and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the construct described by the rule: a non-constant command string is built by concatenating `$target` into a string and passed to `shell_exec()`. The code is in `vulnerabilities/exec/source/medium.php`; the enclosing function is shown as `<unknown>` and appears to be top-level PHP code in the provided snippet.
2. Step 1 / Source: The potentially dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` assigned to `$target` on line 5. The additional requested context for `global:$_REQUEST` and `global:$_POST` is unavailable out-of-snippet, so it does not change this answer. In PHP, `$_REQUEST` and `$_POST` are superglobals populated from request data.
3. Step 2 / Trace: The data flow is `$_REQUEST['ip']` on line 5 → assigned to `$target` on line 5 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → reassigned to `$target` on line 14 → on the Unix branch, `$target` is concatenated into `'ping  -c 4 ' . $target` on line 23 → the resulting command string is passed to `shell_exec()` on line 23. The code path is gated by `isset($_POST['Submit'])` on line 3.
4. Step 3 / Validation, sanitization, or encoding: A blacklist is defined on lines 8-11 and applied on line 14. It removes only the exact substrings `&&` and `;`. This is insufficient for command injection because many shell metacharacters and shell-evaluation forms remain possible, such as `|`, backticks, `$()`, newline command separators, redirection, or other shell syntax. No strict IP allowlist validation such as `filter_var($target, FILTER_VALIDATE_IP)` and no shell escaping such as `escapeshellarg()` is visible.
5. Step 4 / Sink: The sink is `shell_exec()` on line 23. The dangerous operation is OS shell command execution using a command string constructed from user-controlled data: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`.
6. Step 5 / Framework or library protections: No framework-level protection is visible. `shell_exec()` does not automatically parameterize or escape shell arguments. The additional requested global context is unavailable and provides no evidence of an automatic protection or upstream sanitizer.
7. Step 6 / Privilege or authentication needed: From the provided code, the only visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication, authorization, role check, or admin-only guard is visible. Therefore, based only on this context, an attacker appears to need only the ability to send a request with `POST['Submit']` set and an `ip` request parameter. Any stronger access requirement is not visible in provided context.
8. Step 7 / Security impact: If an attacker controls `$_REQUEST['ip']`, the likely impact is OS command injection / remote code execution as the web server or PHP process user, because arbitrary shell syntax can be injected into the command executed by `shell_exec()` on line 23.
9. Step 8 / Weakest link: The weakest link is the incomplete blacklist on lines 8-14 followed by direct command-string concatenation into `shell_exec()` on line 23. The defense is not complete because it neither validates that `$target` is a legitimate IP address nor quotes it safely as a shell argument.
