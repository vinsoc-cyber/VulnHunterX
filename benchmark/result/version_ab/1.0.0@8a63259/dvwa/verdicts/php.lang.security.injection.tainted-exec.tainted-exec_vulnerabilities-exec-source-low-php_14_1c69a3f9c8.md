# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 14 is a shell execution sink using a command string containing `$target`, and `$target` is assigned directly from request-controlled `$_REQUEST['ip']` on line 5. No sanitization, escaping, validation, framework protection, or authentication gate is visible in either the original snippet or the additional context, so the CWE-78 command injection path is clearly present.

## Data flow

HTTP request parameter $_REQUEST['ip'] (vulnerabilities/exec/source/low.php:5) → assigned directly to $target (line 5) → OS branch selects non-Windows path (line 8 to line 12) → $target concatenated into command string 'ping  -c 4 ' . $target (line 14) → command executed by shell_exec() (line 14). Additional requested contexts were unavailable and add no sanitization or reachability constraint.

## Answers

1. Step 0 / flagged line location: The exact flagged line is vulnerabilities/exec/source/low.php:14: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule-described construct is present on that line: `shell_exec()` executes a shell command, and the command string is built by concatenating `$target`. The code is in function `<unknown>`; based on the provided snippet, it appears to be top-level PHP script code rather than a named function.
2. Step 1: The dangerous data originates from HTTP request input at vulnerabilities/exec/source/low.php:5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is a PHP superglobal populated from request-controlled parameters such as GET, POST, and/or COOKIE depending on PHP configuration. The additional context for `global:$_REQUEST` is unavailable and does not change this assessment.
3. Step 2: The data flow is: request-controlled `$_REQUEST['ip']` is read and assigned to `$target` on vulnerabilities/exec/source/low.php:5; the code branches based on OS detection at line 8; in the non-Windows branch, `$target` is concatenated into the command string `'ping  -c 4 ' . $target` on line 14; that command string is passed to `shell_exec()` on line 14. The additional context did not provide any upstream caller or middleware that changes this visible flow.
4. Step 3: No validation, sanitization, escaping, encoding, or allowlisting is visible between line 5 and line 14. There is no `escapeshellarg()`, `escapeshellcmd()`, `filter_var($target, FILTER_VALIDATE_IP)`, regex allowlist, or equivalent protection shown. The provided additional context for authentication/configuration and request filtering is unavailable, so it does not establish any defense.
5. Step 4: The sink is `shell_exec()` at vulnerabilities/exec/source/low.php:14. The dangerous operation is execution of a shell command constructed with attacker-controlled input. If `$target` contains shell metacharacters such as `;`, `&&`, `|`, backticks, or `$()`, it can alter the command executed by the shell.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments. The requested additional context for authentication/configuration and bootstrap/request filtering was unavailable, so no automatic protection can be cited from the provided evidence.
7. Step 6: The visible trigger is vulnerabilities/exec/source/low.php:3: `if( isset( $_POST[ 'Submit' ]  ) )`. No authentication or authorization check is visible in the snippet, and the requested authentication/authorization context was unavailable. Therefore, based on visible code, any requester who can access this script and submit `POST['Submit']` plus an `ip` request parameter can reach the vulnerable code path; no higher privilege requirement is shown.
8. Step 7: The concrete security impact is OS command injection leading to remote command execution as the PHP/web server process. For example, on the non-Windows branch, an attacker-controlled `ip` value can be appended to `ping -c 4` and interpreted by the shell through `shell_exec()` at line 14.
9. Step 8: The weakest link is the direct concatenation of untrusted request input into a shell command: `$_REQUEST['ip']` on line 5 flows into `shell_exec()` on line 14 without visible validation or shell escaping. No complete defense is visible in the original snippet or the additional context.
