# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

Although additional caller/bootstrap context could clarify authentication or routing, the provided slice already shows user-controlled request data reaching `shell_exec()` with only incomplete blacklist filtering. No visible defense in the flagged path prevents command injection.

## Data flow

HTTP request input `$_REQUEST['ip']` at vulnerabilities/exec/source/medium.php:5 → assigned to `$target` at line 5 → partially transformed by blacklist `str_replace()` at lines 8-14 → concatenated into shell command at line 19 → executed by `shell_exec()` at line 19

## Answers

1. Step 0 / flagged line: The flagged line is line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that exact line: `$target` is concatenated into a command string passed to `shell_exec()`.
2. Function location: The snippet labels the function as `<unknown>`. Based on the provided code, the line appears to be in top-level PHP request-handling code rather than inside a named function, but the enclosing route/file-level context is not visible beyond this slice.
3. Source: The potentially dangerous data originates from HTTP request input on line 5: `$target = $_REQUEST[ 'ip' ];`.
4. Relevant chain with file/line references: `vulnerabilities/exec/source/medium.php:5` reads `$_REQUEST['ip']` into `$target`; `vulnerabilities/exec/source/medium.php:8-11` defines a blacklist containing only `&&` and `;`; `vulnerabilities/exec/source/medium.php:14` applies `str_replace()` to remove only those blacklist entries from `$target`; `vulnerabilities/exec/source/medium.php:19` concatenates the resulting `$target` into a shell command and executes it with `shell_exec()` in the Windows branch; `vulnerabilities/exec/source/medium.php:23` does the same in the non-Windows branch.
5. Sanitization assessment: The only visible sanitization is the blacklist on lines 8-14. It is incomplete for shell command execution because it does not enforce an IP-address allowlist and does not use `escapeshellarg()` or equivalent shell-argument escaping.
6. Additional context request: The provided pre-fetched context says `caller:<unknown>` is unavailable. If a second analysis round is required by process, the useful additional context would be the enclosing application entry point or route/controller that includes `vulnerabilities/exec/source/medium.php`, plus any global request filtering/bootstrap code that might transform `$_REQUEST` before line 5.
7. Requested context identifiers: `caller:<unknown>` if the analysis system can resolve the request path; `global:$_REQUEST` or equivalent bootstrap/request-sanitization context if available; and the enclosing file-level include/route context for `vulnerabilities/exec/source/medium.php`.

## Context needed

- caller:<unknown>
- global:$_REQUEST
- function/enclosing-route:vulnerabilities/exec/source/medium.php
