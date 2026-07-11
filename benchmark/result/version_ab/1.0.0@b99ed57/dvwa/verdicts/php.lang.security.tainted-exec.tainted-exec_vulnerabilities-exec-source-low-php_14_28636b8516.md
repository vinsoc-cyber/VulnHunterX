# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and is a real shell execution sink using a command string built from `$target`. User-controlled `$_REQUEST['ip']` flows directly from line 5 to `shell_exec()` on line 14 with no visible escaping, validation, or framework protection, making command injection clearly exploitable on the shown path.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (vulnerabilities/exec/source/low.php:5) → assigned to `$target` (line 5) → non-Windows branch reached after OS check (lines 8-13) → `$target` concatenated into command string and executed by `shell_exec()` (flagged line 14). Additional contexts `global:request_validation` and `global:authentication_middleware` are unavailable and show no intervening sanitization or guard.

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 14 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the rule-described construct: execution of a non-constant shell command via `shell_exec()` with concatenated variable data. It lives in the shown top-level PHP script context; the function is listed as `<unknown>`, and no named function is visible.
2. Step 1: The potentially dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` contains user-controllable request parameters. The new context for `global:request_validation` is unavailable and does not show any validation that changes this answer.
3. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → assigned directly to `$target` on line 5 → OS check at line 8 selects the non-Windows branch for the flagged path → `$target` is concatenated into the command string in `shell_exec('ping  -c 4 ' . $target)` on line 14. The additional requested global contexts are unavailable, so there are no additional visible transformations to add.
4. Step 3: No validation, sanitization, or encoding is visible between the source at line 5 and the sink at line 14. There is no visible `escapeshellarg()`, `escapeshellcmd()`, IP-address allowlist validation, type check, regex validation, or framework filtering. The provided `global:request_validation` context is unavailable, so it provides no visible defense.
5. Step 4: The sink is `shell_exec()` on line 14: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is passing a shell command string containing user-controlled data to the operating-system shell, which can allow command injection.
6. Step 5: No automatic framework or library protection is visible. PHP `shell_exec()` does not automatically escape shell metacharacters or safely separate command arguments. The requested `global:authentication_middleware` and `global:request_validation` contexts are unavailable and do not show any configured protection.
7. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3, and the attacker must control `$_REQUEST['ip']` on line 5. Authentication or authorization requirements are not visible in the provided context; however, no visible auth check prevents the flagged flow.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, they can inject shell metacharacters into the command on line 14, causing arbitrary OS command execution with the privileges of the PHP/web-server process. The concrete impact is command injection/RCE, with possible data theft, system compromise, or denial of service.
9. Step 8: The weakest link is the direct concatenation of untrusted request data into a shell command at line 14 without visible shell-argument escaping or strict IP validation after the assignment at line 5. No complete defense is visible in either the original snippet or the additional unavailable context.
