# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context does not change the analysis because it reveals no upstream validation or protection. The visible code sends user-controlled `$_REQUEST['ip']` through only an incomplete blacklist before concatenating it into a shell command executed by `shell_exec()` on line 23.

## Data flow

HTTP request data in `$_REQUEST['ip']` (line 5; additional `global:$_REQUEST` context unavailable and shows no defense) → assigned to `$target` (line 5) → partial blacklist via `$substitutions` removing only `&&` and `;` (lines 8-14) → transformed `$target` concatenated into `'ping  -c 4 ' . $target` (line 23) → executed by `shell_exec()` (line 23)

## Answers

1. Step 0: The flagged line is present at line 23 and is exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a shell command string built by concatenating `$target`. The enclosing function is listed as `<unknown>`; based on the shown code, this appears to be top-level PHP code rather than a named function.
2. Q1: The potentially dangerous data originates from HTTP request input. On line 5, `$target = $_REQUEST['ip'];` reads the `ip` parameter from PHP's `$_REQUEST` superglobal, which can contain user-controlled request data. The new context for `global:$_REQUEST` is unavailable and does not show any defense that changes this.
3. Q2: Data flow trace: line 3 checks whether `$_POST['Submit']` is set; line 5 assigns `$_REQUEST['ip']` to `$target`; lines 8-11 define a blacklist substitution array; line 14 applies `str_replace(array_keys($substitutions), $substitutions, $target)` to `$target`; line 23 concatenates the transformed `$target` into the command string `'ping  -c 4 ' . $target`; line 23 passes that command string to `shell_exec()`.
4. Q3: The only visible sanitization is the blacklist on lines 8-14. It removes only the substrings `&&` and `;`. This is insufficient for OS command injection because other shell metacharacters and constructs remain possible, such as `|`, backticks, `$()`, newlines, redirections, and command/argument injection through whitespace. No allowlist IP validation, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, or equivalent protection is visible.
5. Q4: The sink is `shell_exec()` on line 23. The dangerous operation is execution of a shell command constructed via string concatenation with request-derived `$target`, allowing attacker-controlled shell syntax to be interpreted by the shell.
6. Q5: No framework or library automatic protection is visible. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and provides no evidence of upstream validation or framework-level protection. PHP `shell_exec()` does not automatically parameterize or safely escape shell arguments.
7. Q6: The code path requires the attacker to make a request where `$_POST['Submit']` is set, as checked on line 3, and to control `$_REQUEST['ip']` on line 5. No authentication or authorization requirement is visible in the provided context, so the visible code suggests any requester who can submit this POST-style request can trigger it.
8. Q7: If the attacker controls `$_REQUEST['ip']`, the concrete security impact is OS command injection leading to remote code execution with the privileges of the PHP/web-server process. This may enable data theft, system compromise, privilege escalation depending on local permissions, or denial of service.
9. Q8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only `&&` and `;`, but does not establish that `$target` is a valid IP address and does not safely quote the shell argument before line 23. Therefore the defense chain is incomplete.
