# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not change the analysis: the visible code clearly takes request-controlled `$_REQUEST['ip']`, applies only an insufficient blacklist, and passes it into `shell_exec()` on line 19. Because no strict validation, shell escaping, or framework protection is visible on this path, the reported tainted command execution issue is exploitable.

## Data flow

source: external request data `$_REQUEST['ip']` at vulnerabilities/exec/source/medium.php:5 → assignment to `$target` at line 5 → partial blacklist transform using `$substitutions` from lines 8-11 via `str_replace()` at line 14 → OS branch at line 17 → sink: concatenation into command string and execution by `shell_exec()` at line 19; additional sibling sink at line 23 for non-Windows

## Answers

1. Step 0 / flagged line location: The flagged line is `vulnerabilities/exec/source/medium.php:19: $cmd = shell_exec( 'ping  ' . $target );`. The rule-described construct is present on that line: a non-constant command is created by concatenating `$target` into a shell command and executed via `shell_exec()`. The code is in Function: `<unknown>` and appears to be top-level script code in the provided snippet.
2. Step 1: The dangerous data originates from user-controlled request input at `vulnerabilities/exec/source/medium.php:5`, where `$target = $_REQUEST[ 'ip' ];`. The requested additional context for `global:$_REQUEST` was unavailable, but in PHP `$_REQUEST` is a request superglobal populated from external request data depending on configuration.
3. Step 2: The data flow is: `$_REQUEST['ip']` is assigned to `$target` on line 5; `$substitutions` is defined on lines 8-11; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; the transformed `$target` is concatenated into a shell command and passed to `shell_exec()` at line 19 in the Windows branch. A sibling non-Windows sink exists at line 23.
4. Step 3: A blacklist is applied on line 14, based on the substitutions defined on lines 8-11. It removes only `&&` and `;`. This is not sufficient for OS command injection because it does not strictly validate `$target` as an IP address and does not use `escapeshellarg()` or equivalent shell-safe argument handling. Other shell metacharacters/separators remain possible depending on platform and shell, such as `&`, `|`, backticks, `$()`, redirection, or newline characters.
5. Step 4: The sink is `shell_exec()` at line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The unsafe operation is executing a shell command string that includes attacker-controlled input. The shell can interpret metacharacters in `$target`, allowing command injection.
6. Step 5: No framework or library automatic protection is visible. The additional requested global context for `$_REQUEST`, `$_POST`, and `variables_order` was unavailable and does not show any automatic protection. PHP `shell_exec()` does not automatically escape command arguments.
7. Step 6: The visible reachability condition is line 3: `if( isset( $_POST[ 'Submit' ]  ) )`. No authentication or authorization checks are visible in the provided code. Based on the visible context, an attacker needs the ability to send a request with `POST['Submit']` set and control `$_REQUEST['ip']`. Whether this endpoint is behind authentication is not visible in provided context.
8. Step 7: The security impact is OS command injection leading to command execution with the privileges of the PHP/web server process. This can result in remote code execution, data theft, file modification, privilege escalation depending on local privileges, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist at lines 8-14. It removes only two command separators, `&&` and `;`, but line 19 still executes a shell command containing request-controlled data without strict IP validation or `escapeshellarg()`.
