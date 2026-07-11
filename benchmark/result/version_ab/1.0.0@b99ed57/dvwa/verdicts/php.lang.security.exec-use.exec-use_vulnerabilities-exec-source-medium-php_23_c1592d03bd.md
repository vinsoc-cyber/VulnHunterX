# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not reveal any upstream defense. The visible code clearly passes attacker-controlled `$_REQUEST['ip']` through only an incomplete blacklist into `shell_exec()` at the flagged line, making this an exploitable OS command injection issue.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` user request input → assigned to `$target`; vulnerabilities/exec/source/medium.php:14 `$target` transformed by `str_replace()` removing only `&&` and `;`; vulnerabilities/exec/source/medium.php:23 `$target` concatenated into `'ping  -c 4 ' . $target`; vulnerabilities/exec/source/medium.php:23 command string executed by `shell_exec()`

## Answers

1. Step 0 / flagged line location: The flagged line is present at vulnerabilities/exec/source/medium.php:23 and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule-described construct is present on that line: `shell_exec()` executes a non-constant command string constructed by concatenating `$target`.
2. Step 1: The dangerous data originates from user-controlled PHP request input at vulnerabilities/exec/source/medium.php:5: `$target = $_REQUEST[ 'ip' ];`. The additional context for `global:_REQUEST` is unavailable and does not change this; `$_REQUEST` is a PHP superglobal populated from request data.
3. Step 2: Data flow is: vulnerabilities/exec/source/medium.php:3 checks that `$_POST['Submit']` is set; line 5 reads `$_REQUEST['ip']` into `$target`; lines 8-11 define a blacklist substitution array; line 14 applies `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigns the result to `$target`; line 17 selects the OS branch; line 23 concatenates `$target` into `'ping  -c 4 ' . $target` and passes it to `shell_exec()`.
4. Step 3: The only visible sanitization is the blacklist replacement on vulnerabilities/exec/source/medium.php:14, using substitutions from lines 8-11. It removes only `&&` and `;`. This is insufficient for shell command injection because other shell control constructs remain possible, including pipes, command substitution with backticks or `$()`, newlines, redirection, and argument injection. There is no visible allowlist IP validation, `escapeshellarg()`, `escapeshellcmd()`, or safe process API.
5. Step 4: The sink is vulnerabilities/exec/source/medium.php:23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The unsafe operation is execution of a shell command string containing attacker-derived data.
6. Step 5: No framework or library protection is visible. The new requested contexts for `global:_REQUEST`, `global:_POST`, and `function:<unknown>` are unavailable, so they provide no additional evidence of upstream validation, authentication, routing protection, parameterization, or escaping. `shell_exec()` itself does not safely separate command arguments from shell syntax.
7. Step 6: The visible trigger condition is vulnerabilities/exec/source/medium.php:3: `if( isset( $_POST[ 'Submit' ]  ) )`. Authentication or authorization requirements are not visible in the provided context or in the additional context. Based on visible code, any requester able to submit `POST['Submit']` and supply `REQUEST['ip']` can reach the sink.
8. Step 7: The concrete security impact is OS command injection, potentially remote command execution as the PHP/web-server process. An attacker controlling `$_REQUEST['ip']` can alter the command executed by `shell_exec()` at line 23 if they use shell syntax not removed by the blacklist.
9. Step 8: The weakest link is the incomplete blacklist at vulnerabilities/exec/source/medium.php:8-14. It attempts to remove only `&&` and `;`, but does not provide complete shell escaping or strict IP allowlist validation before the dangerous command execution at line 23.
