# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The complete source-to-sink path is visible: user-controlled `$_REQUEST['ip']` is assigned to `$target` and directly concatenated into a `shell_exec()` command on the flagged line with no visible sanitization. Additional caller/global/struct context is not needed to establish exploitability for this command-injection sink.

## Data flow

vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → assigned to `$target` at line 5 → concatenated into shell command at line 10 → executed by `shell_exec()` at line 10

## Answers

1. Flagged line re-quoted: line 10 is `$cmd = shell_exec( 'ping  ' . $target );`. It lives in the provided top-level PHP script context; the function is shown as `<unknown>`, and no named function wrapper is visible.
2. The suspicious construct is present on the flagged line: `shell_exec(...)` executes a shell command, and the command string is built by concatenating `'ping  '` with `$target` on line 10.
3. Additional context request assessment: no additional caller, struct, or global context is necessary to determine this finding because the source, propagation, and sink are all visible in the same snippet. The source is a remote/user-controllable PHP superglobal on line 5, and the sink is directly visible on line 10.
4. Relevant chain with file/line references: `vulnerabilities/exec/source/low.php:3` checks only `isset($_POST['Submit'])`; `vulnerabilities/exec/source/low.php:5` assigns `$target = $_REQUEST['ip'];`; `vulnerabilities/exec/source/low.php:8` branches on OS using `php_uname`; `vulnerabilities/exec/source/low.php:10` concatenates `$target` into a command and passes it to `shell_exec`; `vulnerabilities/exec/source/low.php:14` does the same for the non-Windows branch; `vulnerabilities/exec/source/low.php:18` embeds command output in `$html`.
5. No alloc/free/use lifetime chain applies here because this is PHP command injection, not a memory-lifetime issue. The relevant chain is tainted request input → command-string construction → shell execution.
6. No validation or sanitization is visible between the source on line 5 and the sink on line 10. There is no `escapeshellarg()`, `escapeshellcmd()`, or IP allowlist such as `filter_var(..., FILTER_VALIDATE_IP)`.
7. No framework or library automatic protection is visible. PHP `shell_exec()` does not parameterize or safely escape concatenated command arguments.
8. The only visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization requirement is visible in the snippet.
