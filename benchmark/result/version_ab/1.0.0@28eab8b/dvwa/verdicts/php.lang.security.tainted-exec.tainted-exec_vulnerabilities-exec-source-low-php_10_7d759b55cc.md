# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and contains the dangerous sink: `shell_exec()` with a command string built from attacker-controlled `$_REQUEST['ip']` without any visible escaping or validation. Additional caller context could refine required privileges, but it is not critical to determine exploitability of this flagged source-to-sink path.

## Data flow

vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → vulnerabilities/exec/source/low.php:5 `$target` → vulnerabilities/exec/source/low.php:10 string concatenation `'ping  ' . $target` → vulnerabilities/exec/source/low.php:10 `shell_exec(...)`; sibling branch also flows to vulnerabilities/exec/source/low.php:14 `shell_exec('ping  -c 4 ' . $target)`

## Answers

1. Flagged line re-quote / location: Line 10 is present and reads exactly: `$cmd = shell_exec( 'ping  ' . $target );`. It lives in the top-level PHP script context shown as Function: `<unknown>`, not inside a named function in the provided snippet.
2. Vulnerability class: The rule `php.lang.security.tainted-exec.tainted-exec` concerns OS command injection / unsafe command execution. Although the metadata lists CWE-94, the concrete issue at the flagged sink is command injection via `shell_exec()`.
3. Relevant chain with file:line references: In `vulnerabilities/exec/source/low.php:3`, execution is gated by `isset($_POST['Submit'])`. In `vulnerabilities/exec/source/low.php:5`, user-controlled request data is read from `$_REQUEST['ip']` and assigned to `$target`. In `vulnerabilities/exec/source/low.php:8`, the code branches on the operating system. In `vulnerabilities/exec/source/low.php:10`, on Windows, `$target` is concatenated directly into a shell command and passed to `shell_exec()`. In `vulnerabilities/exec/source/low.php:14`, on non-Windows systems, the same `$target` is concatenated directly into a shell command and passed to `shell_exec()`.
4. There is no alloc -> free -> use lifetime chain here because this is PHP command execution, not a memory lifetime finding. The relevant source -> sink chain is request parameter -> variable assignment -> string concatenation -> shell execution.
5. Additional context request assessment: The provided `caller:<unknown>` context is unavailable, and the code is top-level script code rather than a named function. Caller context could clarify authentication/route configuration, but it is not necessary to determine that the flagged sink itself is vulnerable because the source is visible at line 5 and the sink is visible at line 10.
6. No validation, sanitization, or encoding is visible between the source and sink. Specifically, there is no `escapeshellarg()`, `escapeshellcmd()`, IP allowlist validation, or safe argument-vector API before `shell_exec()` on line 10.
7. Framework/library protection: No framework-level automatic protection is visible. PHP `shell_exec()` does not provide automatic shell escaping for concatenated command strings.
8. Weakest link: The weakest link is direct concatenation of `$_REQUEST['ip']`-derived `$target` into the command passed to `shell_exec()` at line 10, with no visible escaping or validation.
