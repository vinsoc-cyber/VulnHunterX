# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context does not change the analysis because it provides no visible sanitization or framework protection. The flagged line 10 clearly executes a shell command containing `$target`, which is assigned directly from user-controlled `$_REQUEST['ip']` on line 5, creating an exploitable command injection path if the script is reachable.

## Data flow

HTTP request superglobal `$_REQUEST['ip']` at vulnerabilities/exec/source/low.php:5 → assigned to `$target` at line 5 → no visible sanitization/validation; added `global:$_REQUEST` and `global:$_POST` context unavailable → concatenated into `'ping  ' . $target` at line 10 → executed by `shell_exec()` at line 10

## Answers

1. Step 0 / flagged line location: The flagged line is line 10 in `vulnerabilities/exec/source/low.php`: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that exact line: `shell_exec()` executes a shell command string that includes concatenated variable data.
2. Function/container identification: The provided context identifies the function as `<unknown>`. The code appears to be top-level PHP script code, not a named function or method. The added context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not identify any enclosing function or framework wrapper.
3. Step 1 source: The dangerous data originates from HTTP request input. On line 5, `$target = $_REQUEST[ 'ip' ];` reads the `ip` request parameter. In PHP, `$_REQUEST` is a superglobal populated from user-controlled request data, depending on configuration. The code path is entered when `$_POST['Submit']` is set on line 3.
4. Step 2 trace: The data flow is: `$_REQUEST['ip']` at line 5 → assigned directly to `$target` at line 5 → no visible transformation or validation → concatenated into the shell command string `'ping  ' . $target` at line 10 → passed to `shell_exec()` at line 10. The non-Windows branch similarly uses `$target` in `shell_exec('ping  -c 4 ' . $target)` on line 14, but the flagged sink is line 10.
5. Step 3 validation/sanitization: No validation, sanitization, shell escaping, or encoding is visible between line 5 and the sink on line 10. There is no `filter_var($target, FILTER_VALIDATE_IP)`, strict IP allowlist, regex validation, `escapeshellarg()`, or `escapeshellcmd()` in the provided code. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not add any visible defense.
6. Step 4 sink: The sink is `shell_exec()` on line 10: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is shell command execution using a string partly controlled by request input. Shell metacharacters in `$target` could change the command that is executed.
7. Step 5 framework/library protections: No framework or library protection is visible. Native PHP `shell_exec()` does not automatically parameterize or safely quote shell arguments. The added global context is unavailable and provides no evidence of upstream request filtering or validation.
8. Step 6 privilege/authentication: The precise authentication state required is not visible in the provided context. The visible trigger is setting `$_POST['Submit']` on line 3 and providing `$_REQUEST['ip']` on line 5. Whether the endpoint is unauthenticated, authenticated-only, or admin-only is not shown.
9. Step 7 concrete impact: If an attacker can reach this code path and control `$_REQUEST['ip']`, the impact is OS command injection leading to remote code execution with the privileges of the PHP/web-server process.
10. Step 8 weakest link: The weakest link is the direct concatenation of `$target`, sourced from `$_REQUEST['ip']` on line 5, into the shell command executed by `shell_exec()` on line 10 without visible validation or escaping. No complete defense is visible in either the original snippet or the added context.
