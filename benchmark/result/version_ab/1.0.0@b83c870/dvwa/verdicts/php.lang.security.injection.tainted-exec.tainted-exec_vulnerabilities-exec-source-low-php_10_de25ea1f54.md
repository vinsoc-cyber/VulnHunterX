# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is visible on line 10 and receives request-derived data from `$_REQUEST['ip']` on line 5 through direct assignment and string concatenation. No validation, allowlisting, shell escaping, framework protection, or other defense is visible in the snippet or additional context, so the Windows branch contains an exploitable OS command injection path.

## Data flow

vulnerabilities/exec/source/low.php:5 user-controlled `$_REQUEST['ip']` → vulnerabilities/exec/source/low.php:5 assigned to `$target` → vulnerabilities/exec/source/low.php:10 concatenated into `'ping  ' . $target` → vulnerabilities/exec/source/low.php:10 executed by `shell_exec(...)`; additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and adds no visible sanitizer or guard

## Answers

1. Step 0 / flagged line: The exact flagged line is line 10: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a shell command, and the command string is built using concatenation with `$target`.
2. Step 1: The potentially dangerous data originates at line 5 from `$_REQUEST['ip']`: `$target = $_REQUEST[ 'ip' ];`. This is PHP request input and is user-controllable. The additional context for `global:$_REQUEST` is unavailable and does not show any overriding type guarantee or sanitizer.
3. Step 2: The data flow is: `$_REQUEST['ip']` at line 5 → assigned directly to `$target` at line 5 → concatenated into the command string `'ping  ' . $target` at line 10 → passed to `shell_exec()` at line 10. The execution path to the flagged line is gated by `isset($_POST['Submit'])` at line 3 and the Windows OS branch `stristr(php_uname('s'), 'Windows NT')` at line 8.
4. Step 3: No validation, sanitization, escaping, or encoding is visible between the source at line 5 and the sink at line 10. There is no visible `escapeshellarg()`, `escapeshellcmd()`, `filter_var(..., FILTER_VALIDATE_IP)`, regex allowlist, or equivalent command-injection defense. The additional `global:$_REQUEST` and `global:$_POST` context is unavailable and does not add any visible defense.
5. Step 4: The sink is `shell_exec()` on line 10. The dangerous operation is executing a shell command constructed by concatenating user-controlled `$target` into `'ping  ' . $target`, which can allow OS command injection.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not parameterize shell commands or automatically escape arguments. The additional global context does not reveal any configured framework protection, request validation, or input filtering.
7. Step 6: The exact authentication or privilege state is not visible in the provided context. The visible reachability condition is that `$_POST['Submit']` must be set at line 3, and the Windows branch must be taken at line 8. No admin-only, authenticated-only, CSRF, or access-control guard is visible.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection leading to remote command execution as the PHP/web server process. Depending on server privileges, this could also enable data theft, lateral movement, or denial of service.
9. Step 8: The weakest link is the direct use of request-derived `$target` from line 5 inside a shell command at line 10 without visible validation or shell argument escaping. No complete defense is visible in the original snippet or the additional context.
