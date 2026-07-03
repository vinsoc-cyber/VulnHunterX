# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is a direct shell execution sink using request-derived `$target`, and the only visible transformation is an inadequate blacklist that does not prevent shell command injection. The additional context did not change the analysis or reveal any upstream validation, authentication gate, or framework protection.

## Data flow

HTTP request input $_REQUEST['ip'] in vulnerabilities/exec/source/medium.php:5 → assigned to $target at line 5 → partial blacklist substitutions defined at lines 8-11 → str_replace removes only '&&' and ';' from $target at line 14 → OS branch reaches non-Windows path at lines 21-23 → $target is concatenated into `'ping  -c 4 ' . $target` and executed by shell_exec at line 23. Additional requested context for global:_REQUEST and global:_POST was unavailable and showed no additional sanitization or guard.

## Answers

1. Step 0 Locate flagged line: line 23 is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `$target` is concatenated into a shell command string passed to `shell_exec`. The code lives in Function: `<unknown>`, apparently top-level PHP script code in `vulnerabilities/exec/source/medium.php`.
2. Step 1 Source: The dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. The additional context for `global:_REQUEST` is unavailable and does not show any preprocessing or protection, so the visible source remains user-controlled request data.
3. Step 2 Trace: `$_REQUEST['ip']` is assigned to `$target` on line 5; `$substitutions` is defined on lines 8-11; `$target` is passed through `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; on the non-Windows branch, `$target` is concatenated into `'ping  -c 4 ' . $target` and executed by `shell_exec` on line 23.
4. Step 3 Validation/Sanitization/Encoding: Lines 8-14 apply a blacklist that removes only `&&` and `;`. This is not sufficient for command injection because other shell metacharacters and command-substitution forms remain possible, such as `|`, backticks, `$()`, newlines, redirection, and shell argument injection. No allowlist IP validation, `escapeshellarg`, `escapeshellcmd`, or equivalent safe command construction is visible. The additional `global:_REQUEST` and `global:_POST` context is unavailable and therefore provides no visible defense.
5. Step 4 Sink: The sink is `shell_exec` on line 23. The dangerous operation is execution of a shell command constructed by string concatenation with request-controlled `$target`.
6. Step 5 Framework/Library protections: No framework or library automatic protections are visible. PHP `shell_exec` executes a command string and does not automatically escape interpolated or concatenated arguments. The additional context did not reveal any framework-level input validation or command-safe abstraction.
7. Step 6 Privilege/authentication: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible in the provided code or additional context, so based on available evidence an attacker only needs the ability to send a request containing `Submit` and `ip` parameters.
8. Step 7 Security impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell syntax into the command executed on line 23, leading to remote command execution as the PHP/web server process.
9. Step 8 Weakest link: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only two command separators before passing the value to `shell_exec`, leaving multiple command-injection vectors available.
