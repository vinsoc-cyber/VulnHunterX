# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.99) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

Step 0 confirmed the flagged line is present exactly as `$cmd = shell_exec( 'ping  -c 4 ' . $target );` at line 14 in top-level PHP script context, function `<unknown>`. The source-to-sink path is visible from `$_REQUEST['ip']` on line 5 to `shell_exec()` on line 14 with no visible validation or escaping, and the additional requested context was unavailable and did not reveal any defense.

## Data flow

`$_REQUEST['ip']` user request input (vulnerabilities/exec/source/low.php:5) → `$target` assignment (line 5) → OS branch reaches non-Windows path (lines 12-15) → `$target` concatenated into command string `'ping  -c 4 ' . $target` (line 14) → command executed by `shell_exec()` (line 14) → output assigned to `$cmd` (line 14) and displayed in `$html` (line 18)

## Answers

1. Step 1: The dangerous data originates from HTTP request input: `$target = $_REQUEST['ip'];` at `vulnerabilities/exec/source/low.php:5`. The additional `global:_REQUEST` context is unavailable, but in PHP `$_REQUEST` is a request superglobal containing user-supplied request data.
2. Step 2: Data flow: `$_REQUEST['ip']` at line 5 → assigned directly to `$target` at line 5 → on the non-Windows branch, `$target` is concatenated into `'ping  -c 4 ' . $target` at line 14 → the resulting command string is passed to `shell_exec()` at line 14 → command output is assigned to `$cmd` at line 14 → `$cmd` is embedded into `$html` at line 18.
3. Step 3: No validation, sanitization, or encoding is visible between the source and sink. Specifically, there is no IP allowlist/format check, no `filter_var($target, FILTER_VALIDATE_IP)`, no `escapeshellarg()`, and no `escapeshellcmd()` before line 14. The new additional context for `global:_REQUEST` and `global:_POST` is unavailable and does not show any defense.
4. Step 4: The sink is the flagged line, `vulnerabilities/exec/source/low.php:14`: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is execution of a shell command constructed by concatenating user-controlled data into the command string.
5. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell arguments. The added global context is unavailable and shows no framework-level filtering or escaping.
6. Step 6: The code path is gated by `isset($_POST['Submit'])` at line 3. No authentication or authorization check is visible in the provided code. Based on the visible context, an attacker only needs to be able to send a request with `POST['Submit']` set and provide `ip` through `$_REQUEST`.
7. Step 7: If an attacker controls `ip`, they can inject shell metacharacters into the command executed at line 14, causing arbitrary OS command execution as the PHP/web-server process. Concrete impact is remote command execution, which can lead to data theft, server compromise, lateral movement, or denial of service.
8. Step 8: The weakest link is direct concatenation of `$target`, sourced from `$_REQUEST['ip']` at line 5, into a shell command at line 14 without any visible validation or shell-argument escaping. No complete defense is visible in the provided or additional context.
