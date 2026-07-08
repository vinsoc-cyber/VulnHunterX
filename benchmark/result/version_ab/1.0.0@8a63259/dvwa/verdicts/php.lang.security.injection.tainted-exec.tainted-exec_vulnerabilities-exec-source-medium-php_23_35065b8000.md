# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not change the visible source-to-sink chain: user-controlled `$_REQUEST['ip']` flows into `$target`, receives only an insufficient blacklist replacement, and is then concatenated into a `shell_exec` command at line 23. This is a clear CWE-78 command injection path with no adequate visible validation or escaping.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` user input → vulnerabilities/exec/source/medium.php:5 assigned to `$target` → vulnerabilities/exec/source/medium.php:8-11 blacklist defines removal of only `&&` and `;` → vulnerabilities/exec/source/medium.php:14 `str_replace(...)` partially transforms and reassigns `$target` → vulnerabilities/exec/source/medium.php:23 `$target` concatenated into `ping -c 4` command → vulnerabilities/exec/source/medium.php:23 executed by `shell_exec`

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/medium.php:23 and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule-described construct is present on that line: request-derived data in `$target` is concatenated into a command string passed to `shell_exec`, which executes a shell command.
2. Step 1: The dangerous data originates from HTTP request input at vulnerabilities/exec/source/medium.php:5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is PHP request data and can include user-controlled GET, POST, and/or COOKIE parameters depending on configuration. The additional context for `global:$_REQUEST` is unavailable and does not show any overriding safety guarantee.
3. Step 2: Data flow with all visible assignments and transformations: `$_REQUEST['ip']` at line 5 → assigned to `$target` at line 5 → blacklist array `$substitutions` is defined at lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigned to `$target` at line 14 → OS branch is selected at lines 17-24 → in the non-Windows branch, `$target` is concatenated into `'ping  -c 4 ' . $target` and executed by `shell_exec` at line 23.
4. Step 3: The only visible sanitization is the blacklist replacement at lines 8-14, which removes only `&&` and `;`. This is not sufficient for CWE-78 OS command injection because other shell metacharacters and command-substitution mechanisms remain possible, including `|`, single `&`, backticks, `$()`, newlines, redirections, and other shell syntax. There is no visible strict IP-address allowlist validation and no `escapeshellarg()` or equivalent shell-safe escaping. The additional context provided is unavailable and does not add any sanitizer or validation.
5. Step 4: The sink is vulnerabilities/exec/source/medium.php:23: `shell_exec( 'ping  -c 4 ' . $target );`. The unsafe operation is shell command execution using a command string built by concatenating user-controlled input.
6. Step 5: No framework or library automatic protection is visible. `shell_exec` executes a shell command string and does not provide argument parameterization or shell escaping. The additional context does not reveal any framework-level validation, route guard, or wrapper that would protect this sink.
7. Step 6: The visible trigger condition is vulnerabilities/exec/source/medium.php:3: `if( isset( $_POST[ 'Submit' ]  ) )`. No authentication or authorization check is visible in the provided code. Based on visible evidence, an attacker who can send a request with `POST['Submit']` set and an `ip` request parameter can reach the sink. Any stronger authentication state is not visible in provided context.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection leading to remote command execution as the PHP/web server process. This may allow data theft, server compromise, privilege escalation within the host context, or denial of service depending on process privileges.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-14 before direct shell execution on line 23. The defense chain is incomplete because it neither strictly validates `$target` as an IP address nor safely escapes it as a shell argument.
