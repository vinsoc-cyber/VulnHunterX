# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 19 is present and exactly contains `shell_exec( 'ping  ' . $target )`, with `$target` derived from user-controlled `$_REQUEST['ip']` on line 5. The only visible defense is an incomplete blacklist on line 14 that removes only `&&` and `;`, leaving an exploitable command-injection path to the shell execution sink.

## Data flow

HTTP request parameter $_REQUEST['ip'] (vulnerabilities/exec/source/medium.php:5) → assigned to $target (line 5) → incomplete blacklist $substitutions removes only '&&' and ';' (lines 8-11) → str_replace applied to $target (line 14) → concatenated into shell command in shell_exec('ping  ' . $target) at flagged line 19. Additional requested global contexts for $_REQUEST and $html are unavailable and add no visible defense.

## Answers

1. Step 1 / Source: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` is assigned to `$target` on line 5. The additional context for `global:$_REQUEST` is unavailable and does not change this; in PHP, `$_REQUEST` is a request superglobal containing user-controllable request parameters.
2. Step 2 / Trace: `$_REQUEST['ip']` on line 5 → assigned to `$target` on line 5 → blacklist array `$substitutions` defined on lines 8-11 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → `$target` concatenated into the shell command at the flagged sink on line 19: `$cmd = shell_exec( 'ping  ' . $target );`. A similar sink also exists on line 23 for the non-Windows branch, but the flagged sink under review is line 19.
3. Step 3 / Validation/Sanitization: The only visible sanitization is blacklist replacement on line 14, using substitutions defined on lines 8-11 to remove only `&&` and `;`. This is insufficient for OS command injection because other shell metacharacters or command-substitution mechanisms remain possible, such as `|`, single `&`, backticks, `$()`, redirection, newline injection, or platform-specific shell syntax. There is no visible allowlist validation for a valid IP address and no use of `escapeshellarg()` or equivalent shell-safe argument handling.
4. Step 4 / Sink: The exact flagged line 19 is: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: user-influenced data is concatenated into a string passed to `shell_exec()`, which executes a shell command. The function context is listed as `<unknown>` in the provided finding; the code appears to be top-level PHP in `vulnerabilities/exec/source/medium.php`.
5. Step 5 / Framework or Library Protections: No framework or library automatic protection is visible. `shell_exec()` does not parameterize command arguments or automatically escape shell metacharacters. The additional context for `global:$html` is unavailable and is not relevant to protecting the shell execution sink.
6. Step 6 / Required Privilege/Auth State: The visible reachability condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible in the provided context, so the required privilege level is not visible. Based only on the shown code, any requester able to submit the relevant POST parameter could reach the path.
7. Step 7 / Security Impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell syntax into the command executed by `shell_exec()` on line 19, causing remote command execution as the PHP/web server process. This can lead to data theft, server compromise, or pivoting depending on process privileges.
8. Step 8 / Weakest Link: The weakest link is the incomplete blacklist sanitization on line 14. Removing only `&&` and `;` does not form a complete defense against command injection. A complete defense would require strict IP-address validation and/or safe shell argument escaping, neither of which is visible.
