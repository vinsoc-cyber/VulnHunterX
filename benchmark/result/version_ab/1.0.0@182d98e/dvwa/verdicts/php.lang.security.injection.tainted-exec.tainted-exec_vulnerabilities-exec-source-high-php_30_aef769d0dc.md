# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is present and is a `shell_exec()` sink using `$target`, which comes from `$_REQUEST['ip']`. The only visible defense is an incomplete blacklist, not robust shell escaping or strict allowlist validation, so the command-injection path is clearly present.

## Data flow

`$_REQUEST['ip']` source at vulnerabilities/exec/source/high.php:5 → `trim()` into `$target` at line 5 → blacklist `str_replace(...)` at line 21 → concatenation into shell command and `shell_exec()` at line 30

## Answers

1. Flagged line located: line 30 is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: user-influenced data is concatenated into a string passed to PHP `shell_exec()`. The code is not inside a named function in the provided snippet; it appears to live at top-level script scope in `vulnerabilities/exec/source/high.php`.
2. Vulnerability class: CWE-78 OS command injection. The dangerous operation is execution of a shell command via `shell_exec()` with request-derived input.
3. Source: user-controlled HTTP input is read from `$_REQUEST['ip']` on line 5, gated only by `isset($_POST['Submit'])` on line 3.
4. Transformations: line 5 applies `trim()` to `$_REQUEST['ip']` and assigns it to `$target`; lines 8-18 define a blacklist; line 21 applies `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigns `$target`; line 30 concatenates `$target` into the command string.
5. Sanitization assessment: the blacklist on lines 8-21 is not a complete shell-argument sanitizer. It removes some metacharacters but does not use `escapeshellarg()`, strict IP allowlist validation, or an argument-safe process API. No complete defense is visible before line 30.
6. Sink: line 30 calls `shell_exec('ping  -c 4 ' . $target)`. Passing a concatenated command string to the shell is dangerous because shell syntax in `$target` can alter command execution.
7. Framework/library protection: none is visible. PHP `shell_exec()` does not automatically parameterize or escape arguments.
8. Reachability/authentication: the visible path is reachable when `$_POST['Submit']` is set on line 3. Authentication or role checks are not visible in the provided context, but lack of authentication context does not change the command-injection sink shown here.
9. Relevant chain with file:line references: `vulnerabilities/exec/source/high.php:5` reads `$_REQUEST['ip']` → `vulnerabilities/exec/source/high.php:21` applies incomplete blacklist replacement → `vulnerabilities/exec/source/high.php:30` passes the resulting `$target` to `shell_exec()`.
10. Additional context request assessment: caller context is unavailable and no named function exists in the snippet. Additional context such as `caller:<unknown>`, `global:$html`, or routing/authentication configuration could clarify exposure, but it is not required to determine that the flagged sink itself is vulnerable because the source-to-sink flow and insufficient sanitization are visible.
