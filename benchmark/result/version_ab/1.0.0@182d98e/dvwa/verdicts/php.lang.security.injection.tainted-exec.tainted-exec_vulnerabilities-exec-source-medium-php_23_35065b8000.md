# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is present on line 23 and executes a shell command containing `$target`, which comes directly from `$_REQUEST['ip']` on line 5. The only visible transformation is an incomplete blacklist on lines 8-14, which is inadequate for shell command injection, and the additional context did not reveal any protective validation or framework guard.

## Data flow

HTTP request source `$_REQUEST['ip']` in `vulnerabilities/exec/source/medium.php` line 5 → assigned to `$target` on line 5 → partial blacklist substitutions defined on lines 8-11 → `$target` transformed by `str_replace()` on line 14, removing only `&&` and `;` → OS branch on lines 17-24 → non-Windows sink `shell_exec('ping  -c 4 ' . $target)` on flagged line 23. Additional requested global context for `$_REQUEST`, `$_POST`, and `$html` was unavailable and adds no visible sanitization or guard.

## Answers

1. Step 0 / Flagged line location: The flagged line is present at line 23 and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the rule-described dangerous construct: a PHP shell execution function, `shell_exec()`, called with a command string built by concatenating `$target`.
2. Step 1 / Source: The dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` assigned to `$target` on line 5. The only visible gate is `isset($_POST['Submit'])` on line 3, which is also request-controlled. The newly provided `global:$_REQUEST` and `global:$_POST` context is unavailable and does not show any additional protection.
3. Step 2 / Trace: `$_REQUEST['ip']` is assigned to `$target` on line 5. `$substitutions` is defined on lines 8-11 to remove only `&&` and `;`. `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14. On the non-Windows branch, `$target` is concatenated into the command passed to `shell_exec()` on line 23.
4. Step 3 / Validation, sanitization, or encoding: Lines 8-14 implement a blacklist that removes only `&&` and `;`. This is not sufficient for shell command injection because many shell metacharacters and command-substitution mechanisms remain possible, including `|`, single `&`, backticks, `$()`, newlines, redirection operators, and argument injection. No allowlist IP validation, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, `escapeshellcmd()`, or safe process API is visible. The additional global contexts are unavailable and do not add any visible sanitizer.
5. Step 4 / Sink: The sink is line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is execution of a shell command constructed by string concatenation with user-controlled data.
6. Step 5 / Framework or library protections: No framework or library protection is visible. PHP `shell_exec()` does not automatically parameterize or escape command arguments; it executes the provided command string through the shell. The newly provided context for `$_REQUEST`, `$_POST`, and `$html` is unavailable and does not reveal any automatic protection.
7. Step 6 / Privilege or authentication needed: Not visible in provided context. The only visible condition is that `$_POST['Submit']` is set on line 3. No authentication, authorization, role check, or admin-only guard is shown. Therefore, from the provided code, any requester able to submit the expected POST parameter and `ip` value can reach the path.
8. Step 7 / Security impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell syntax into the command executed on line 23, leading to OS command injection / remote command execution as the web server or PHP process user. This may allow data theft, system compromise, privilege escalation depending on local permissions, or denial of service.
9. Step 8 / Weakest link: The weakest link is the incomplete blacklist on lines 8-14. It removes only `&&` and `;`, but does not enforce that `$target` is an IP address and does not safely quote the value before shell execution. No complete defense is visible in the original or additional context.
