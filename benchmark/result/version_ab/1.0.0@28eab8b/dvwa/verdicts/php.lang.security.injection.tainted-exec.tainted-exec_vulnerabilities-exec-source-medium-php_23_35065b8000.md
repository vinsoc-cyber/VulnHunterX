# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged shell-execution sink is visible at line 23 and receives attacker-controlled request data from line 5 after only an inadequate blacklist on lines 8-14. No additional caller, struct, or global context is required to establish command injection on this visible path.

## Data flow

vulnerabilities/exec/source/medium.php:5 $_REQUEST['ip'] → $target; vulnerabilities/exec/source/medium.php:8-11 blacklist defines only '&&' and ';'; vulnerabilities/exec/source/medium.php:14 str_replace() removes only those tokens; vulnerabilities/exec/source/medium.php:23 $target is concatenated into shell_exec('ping  -c 4 ' . $target)

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/medium.php:23 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It contains the construct described by the rule: user-influenced data concatenated into an argument to `shell_exec()`, a shell-command execution sink.
2. Function location: The snippet reports Function: `<unknown>`. No named function is visible; the code appears at top level or in an unknown included PHP context. The sink itself is visible and does not depend on an unseen callee body because `shell_exec()` is a PHP built-in.
3. Additional context request assessment: I cannot validly mark this as Needs More Data merely to perform another round, because the flagged line is visible, the remote source is visible, the transformation is visible, and the sink is a known PHP built-in. Caller context is not critical to decide exploitability here. If more context were nevertheless desired for triage metadata, the only relevant optional request would be `caller:<unknown>`, but the provided pre-fetched context says it is unavailable.
4. Step 1: The dangerous data originates from HTTP request input at vulnerabilities/exec/source/medium.php:5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is attacker-controllable request data. Line 3 only checks whether `$_POST['Submit']` is set; it does not validate `ip`.
5. Step 2: Data flow chain with concrete references: vulnerabilities/exec/source/medium.php:5 assigns `$_REQUEST['ip']` to `$target`; lines 8-11 define a blacklist containing only `&&` and `;`; line 14 applies `str_replace()` to remove those blacklist entries from `$target`; line 23 concatenates the resulting `$target` into `'ping  -c 4 ' . $target` and passes it to `shell_exec()`.
6. Step 3: The only visible transformation is blacklist replacement on line 14 using substitutions from lines 8-11. This is insufficient for command injection because it removes only `&&` and `;`, leaving other shell metacharacters and command-substitution mechanisms such as `|`, backticks, `$()`, newlines, redirection, and other shell syntax. No strict IP validation, allowlist, `escapeshellarg()`, or safe process API is visible.
7. Step 4: The sink is `shell_exec()` at vulnerabilities/exec/source/medium.php:23. The dangerous operation is invoking a shell command built by string concatenation with attacker-controlled input.
8. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically parameterize or safely escape concatenated shell arguments.
9. Step 6: The visible trigger condition is `isset($_POST['Submit'])` at line 3 plus an `ip` request parameter at line 5. No authentication or authorization check is visible in the provided code, and the scanner’s remote source establishes external reachability for this tainted path.
10. Step 7: If an attacker controls `$target`, the impact is command injection / remote code execution as the PHP/web-server process user, with potential data theft, system compromise, or denial of service.
11. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It is not a complete command-injection defense and leaves exploitable shell syntax before the value reaches `shell_exec()` on line 23.
