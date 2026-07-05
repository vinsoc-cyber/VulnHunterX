# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and directly executes a non-constant shell command using `$target`, which comes from user-controlled `$_REQUEST['ip']` with no visible validation or escaping. The additional context is unavailable and does not reveal any defense, so the visible path remains clearly exploitable for command injection.

## Data flow

HTTP request input `$_REQUEST['ip']` in `vulnerabilities/exec/source/low.php:5` → assigned to `$target` in `vulnerabilities/exec/source/low.php:5` → OS branch selects non-Windows path in `vulnerabilities/exec/source/low.php:8-15` → `$target` concatenated into `'ping  -c 4 ' . $target` in `vulnerabilities/exec/source/low.php:14` → executed by `shell_exec()` in `vulnerabilities/exec/source/low.php:14`. Additional requested contexts `global:access_control` and `global:bootstrap` are unavailable and add no visible validation or protection.

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 14 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This is in Function: `<unknown>` according to the provided finding, apparently top-level PHP script context in `vulnerabilities/exec/source/low.php`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command built by concatenating `$target`.
2. Step 1: The potentially dangerous data originates from HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` is user-controllable request data. The new additional context for `global:access_control` and `global:bootstrap` is unavailable, so it does not change this answer.
3. Step 2: The data flow is: user-controlled `$_REQUEST['ip']` at line 5 → direct assignment to `$target` at line 5 → `$target` is concatenated into the command string at line 14 → the resulting command is passed to `shell_exec()` at line 14. The OS branch at lines 8-15 determines whether the Unix sink at line 14 is reached; for non-Windows systems, the line 14 sink is reachable when `isset($_POST['Submit'])` is true at line 3.
4. Step 3: No validation, sanitization, escaping, or encoding is visible between line 5 and line 14. There is no visible `escapeshellarg()`, `escapeshellcmd()`, IP allowlist, or `filter_var($target, FILTER_VALIDATE_IP)`. The additional requested globals are unavailable and show no defense.
5. Step 4: The sink is `shell_exec()` at line 14. The unsafe operation is executing a shell command constructed with user-controlled input: `'ping  -c 4 ' . $target`. Shell metacharacters in `$target` can change the command executed.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments. The provided `global:access_control` and `global:bootstrap` contexts are unavailable, so they provide no visible protection that can be cited.
7. Step 6: Based on the visible code, an attacker must trigger the block by setting `$_POST['Submit']` at line 3 and control `$_REQUEST['ip']` at line 5. No authentication or authorization requirement is visible in the snippet or in the additional context, because the requested global contexts are unavailable.
8. Step 7: The concrete security impact is OS command injection, potentially remote code execution as the user running the PHP/web server process. On the Unix branch at line 14, attacker-controlled shell syntax could append or alter commands.
9. Step 8: The weakest link is the direct use of user-controlled request data from line 5 in a shell command at line 14 without any visible validation or shell escaping. No complete defense is visible in the provided code or added context.
