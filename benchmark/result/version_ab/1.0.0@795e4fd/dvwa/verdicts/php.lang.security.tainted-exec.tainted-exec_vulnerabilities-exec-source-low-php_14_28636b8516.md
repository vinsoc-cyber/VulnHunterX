# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line executes a shell command constructed with user-controlled `$_REQUEST['ip']` and no visible sanitization. Additional caller context may affect authentication requirements, but it is not needed to determine that the shown command-execution path is vulnerable.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (`vulnerabilities/exec/source/low.php:5`) → `$target` assignment with no validation (`line 5`) → command-string concatenation (`line 14`) → `shell_exec()` execution sink (`line 14`)

## Answers

1. Step 0 / flagged line: The flagged line 14 is present and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The rule-described construct is present on that line: a non-constant command string is passed to `shell_exec()` after concatenating `$target`.
2. Function location: The provided context labels the function as `<unknown>`. The code appears to be top-level PHP code in `vulnerabilities/exec/source/low.php`, guarded by `if( isset( $_POST[ 'Submit' ]  ) )` on line 3. No named function or class scope is visible.
3. Additional context request assessment: `caller:<unknown>` was pre-fetched and unavailable. No `struct:<name>` is applicable to this PHP snippet, and no relevant `global:<name>` declaration is referenced. The sink is PHP’s built-in `shell_exec()`, whose behavior is known: it executes the provided command string through the shell; no callee body is needed.
4. Step 1: The dangerous data originates from HTTP request input: `$target = $_REQUEST[ 'ip' ];` on line 5. `$_REQUEST` is user-controllable request data.
5. Step 2: The relevant chain is request input `$_REQUEST['ip']` at `vulnerabilities/exec/source/low.php:5` → assignment to `$target` at line 5 → concatenation into `'ping  -c 4 ' . $target` at line 14 → execution by `shell_exec()` at line 14. There is no alloc/free/use lifetime chain here because this is PHP command execution, not a memory-lifetime issue.
6. Step 3: No validation, sanitization, or encoding is visible between line 5 and line 14. There is no `escapeshellarg()`, `escapeshellcmd()`, IP allowlist, or `filter_var($target, FILTER_VALIDATE_IP)`.
7. Step 4: The sink is `shell_exec()` at line 14. The unsafe operation is execution of a shell command containing attacker-controlled data.
8. Step 5: No framework/library automatic protection is visible. PHP `shell_exec()` does not automatically escape arguments.
9. Step 6: The code path is gated by `isset($_POST['Submit'])` at line 3. Authentication state is not visible in provided context, but any actor who can trigger this PHP file with that POST parameter can reach the sink.
10. Step 7: The security impact is OS command injection/RCE as the PHP/web-server process user, because shell metacharacters in `$_REQUEST['ip']` can alter the command executed at line 14.
11. Step 8: The weakest link is direct concatenation of untrusted request data into a shell command at line 14 without escaping or validation.
