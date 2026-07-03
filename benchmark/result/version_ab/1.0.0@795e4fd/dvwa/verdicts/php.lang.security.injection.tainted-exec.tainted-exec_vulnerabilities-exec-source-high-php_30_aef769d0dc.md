# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not reveal any upstream defense. The visible code clearly allows request-controlled `$_REQUEST['ip']` to reach `shell_exec()` on line 30 after only incomplete blacklist filtering, with concrete bypasses such as an internal newline remaining possible.

## Data flow

`vulnerabilities/exec/source/high.php:5` user input `$_REQUEST['ip']` → `trim()` and assignment to `$target` at line 5 → blacklist array defined at lines 8-18 → incomplete `str_replace(...)` sanitization at line 21 → OS branch at lines 24-31 → `$target` concatenated into `shell_exec('ping  -c 4 ' . $target)` at line 30

## Answers

1. Step 0 / flagged line location: The flagged line is line 30 in `vulnerabilities/exec/source/high.php`: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule-described construct is present on that line: `$target` is concatenated into a command string passed to `shell_exec()`. The function is listed as `<unknown>`; the snippet appears to be top-level PHP code guarded by the condition on line 3.
2. Step 1: The dangerous data originates from HTTP request input at line 5: `$target = trim($_REQUEST[ 'ip' ]);`. `$_REQUEST['ip']` is user-controlled request data. The new context for `global:_REQUEST` and `global:_POST` is unavailable, so it does not change this answer.
3. Step 2: Data flow through assignments and transformations: line 5 reads `$_REQUEST['ip']`, applies `trim()`, and assigns it to `$target`; lines 8-18 define a blacklist substitution array; line 21 applies `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigns the result to `$target`; line 30 concatenates `$target` into `'ping  -c 4 ' . $target` and passes it to `shell_exec()`.
4. Step 3: There is attempted sanitization on line 21 using blacklist replacement with values from lines 8-18. This is insufficient for command injection because it does not enforce a valid IP-address allowlist and does not use `escapeshellarg()` or a safe argument-vector process API. For example, the blacklist does not remove an internal newline; `trim()` on line 5 only removes leading/trailing whitespace, so an input like `127.0.0.1\nid` can still introduce a separate shell command on Unix-like shells.
5. Step 4: The sink is `shell_exec()` on line 30. The dangerous operation is shell execution of a string built by concatenating user-influenced `$target` into the command.
6. Step 5: No automatic framework or library protection is visible. The additional requested context was unavailable and shows no upstream validation. `shell_exec()` does not parameterize shell arguments or automatically escape user input.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization checks are visible in the provided code or additional context, so the code appears reachable by anyone able to send a request with `Submit` set, subject to deployment routing not shown.
8. Step 7: The concrete security impact is OS command injection leading to remote code execution as the PHP/web-server process user. On the flagged Unix-like branch at lines 28-30, attacker-controlled data can alter the shell command executed by `shell_exec()`.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-21 combined with direct command-string concatenation into `shell_exec()` on line 30. The defense is not complete because bypass characters such as internal newlines are not removed and no strict IP validation or safe shell escaping is applied.
