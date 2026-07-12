# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible and contains a `shell_exec()` sink using request-controlled `$target`. The only visible defense is an incomplete blacklist, not a complete shell-argument escaping or strict IP validation defense, so the command injection path is clearly exploitable.

## Data flow

vulnerabilities/exec/source/high.php:5 `$_REQUEST['ip']` → `trim()` into `$target` → vulnerabilities/exec/source/high.php:21 incomplete blacklist `str_replace()` → vulnerabilities/exec/source/high.php:30 concatenation into shell command → vulnerabilities/exec/source/high.php:30 `shell_exec()`

## Answers

1. Flagged line location: line 30 is present and reads exactly: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the rule-described construct: execution of a non-constant command via `shell_exec()` with concatenated variable input.
2. Function/context: The code is not inside a named function in the provided snippet; the reported function is `<unknown>`. The code appears to execute in top-level PHP request-handling context gated by `isset($_POST['Submit'])` on line 3.
3. Relevant chain with file/line references: In `vulnerabilities/exec/source/high.php:5`, request data is read from `$_REQUEST['ip']` and assigned to `$target` after `trim()`. In `vulnerabilities/exec/source/high.php:8-18`, a blacklist substitution array is defined. In `vulnerabilities/exec/source/high.php:21`, `$target` is modified using `str_replace()` with that blacklist. In `vulnerabilities/exec/source/high.php:30`, `$target` is concatenated into a shell command and passed to `shell_exec()`.
4. Additional context request assessment: Caller context such as `caller:<unknown>` is not necessary to determine the flagged sink’s exploitability because the scanner/source context shows attacker-controlled HTTP input via `$_REQUEST` reaching `shell_exec()` in the same snippet. No struct or global variable definitions are involved in this PHP data flow.
5. Sanitization assessment: The blacklist on lines 8-21 is incomplete for shell command injection. It does not use `escapeshellarg()`, `escapeshellcmd()`, or strict IP address allowlist validation. It also leaves possible shell metacharacter usage, such as a bare pipe `|` not followed by a space, because only `'| '` is removed on line 12.
6. Sink assessment: The dangerous sink is `shell_exec()` on line 30. The unsafe operation is shell command construction by concatenating attacker-controlled `$target` into `'ping  -c 4 ' . $target`.
7. Framework/library protection assessment: No framework or library protection is visible. PHP `shell_exec()` does not automatically make concatenated command arguments safe.
8. Security impact: Successful exploitation allows OS command injection / remote code execution under the privileges of the PHP/web server process.
