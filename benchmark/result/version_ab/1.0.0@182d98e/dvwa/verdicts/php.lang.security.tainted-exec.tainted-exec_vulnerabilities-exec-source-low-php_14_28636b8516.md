# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is present and executes a shell command built from `$target`, which is assigned directly from `$_REQUEST['ip']` with no visible sanitization. Additional caller context could clarify authentication or routing, but it is not necessary to establish exploitability of this flagged sink when the shown code path is reachable via request parameters.

## Data flow

vulnerabilities/exec/source/low.php:5 `$_REQUEST['ip']` → vulnerabilities/exec/source/low.php:5 `$target` → vulnerabilities/exec/source/low.php:14 string concatenation into `'ping  -c 4 ' . $target` → vulnerabilities/exec/source/low.php:14 `shell_exec()`

## Answers

1. Flagged line located: vulnerabilities/exec/source/low.php:14 contains exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command string built by concatenating `$target`.
2. Function/scope: The provided context identifies Function as `<unknown>`. The code appears to be top-level PHP script code rather than a named function in the provided snippet; no enclosing named function is visible.
3. Vulnerability class: command injection / OS command execution via tainted input reaching `shell_exec()`. The rule labels CWE-94, but the concrete issue at this sink is shell command injection.
4. Source: User-controlled request data originates at vulnerabilities/exec/source/low.php:5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is PHP superglobal request input.
5. Relevant chain with concrete references: request gate `isset($_POST['Submit'])` at vulnerabilities/exec/source/low.php:3 → tainted request parameter assigned to `$target` at line 5 → OS branch chooses the non-Windows path at lines 8 and 12-13 → `$target` concatenated into shell command and executed by `shell_exec()` at line 14 → output interpolated into `$html` at line 18.
6. Validation/sanitization: No validation or sanitization is visible between the source on line 5 and the sink on line 14. There is no visible IP validation, allowlist, `escapeshellarg()`, or equivalent safe argument handling.
7. Sink: vulnerabilities/exec/source/low.php:14, `shell_exec( 'ping  -c 4 ' . $target )`. The dangerous operation is shell execution of a command string containing untrusted input.
8. Additional context requested per your instruction, although the shown source-to-sink chain is already complete for this sink: `caller:<unknown>` or the enclosing route/controller/template that includes this top-level PHP file, and `global:$_REQUEST`/request initialization context if available. No PHP struct/class context is visible or relevant in this snippet.
