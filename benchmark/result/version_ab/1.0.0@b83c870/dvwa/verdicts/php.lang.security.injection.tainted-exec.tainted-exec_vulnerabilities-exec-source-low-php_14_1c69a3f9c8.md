# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line 14 is a `shell_exec` call whose command string includes `$target`, which is assigned directly from user-controlled `$_REQUEST['ip']` on line 5. No visible validation, shell escaping, or framework protection exists in the snippet or the additional unavailable global context, so the shown path is clearly exploitable as command injection/RCE.

## Data flow

source: user-controlled HTTP request value `$_REQUEST['ip']` at `vulnerabilities/exec/source/low.php:5` → assignment to `$target` at line 5 → no visible validation/sanitization/escaping; additional `global:$_REQUEST`, `global:$_POST`, and `global:$html` contexts unavailable → concatenation into command string `'ping  -c 4 ' . $target` at line 14 → sink: `shell_exec(...)` executes that command at line 14 → output assigned to `$cmd` and rendered in `$html` at line 18

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 14 and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This line contains the construct described by the rule: user-influenced data is concatenated into a string passed to `shell_exec`, a PHP shell command execution sink. The code appears to be top-level script scope in `vulnerabilities/exec/source/low.php`; no named enclosing function is visible.
2. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` assigned to `$target` on line 5. `$_REQUEST` is a PHP superglobal that can contain user-controlled request values. The additional `global:$_REQUEST` context is unavailable and does not show any constraint or sanitizer.
3. Step 2: Data flow trace: `$_POST['Submit']` is checked on line 3 only as a trigger condition; `$_REQUEST['ip']` is read on line 5 and assigned directly to `$target`; `$target` is concatenated into the command string on line 14; the resulting string is passed to `shell_exec` on line 14. The command output is later inserted into `$html` on line 18, but the relevant sink for this rule is line 14.
4. Step 3: No validation, sanitization, escaping, or encoding is visible. There is no IP validation such as `filter_var($target, FILTER_VALIDATE_IP)`, no allowlist, and no shell escaping such as `escapeshellarg()` or `escapeshellcmd()` between lines 5 and 14. The additional global contexts for `$_REQUEST`, `$_POST`, and `$html` are unavailable and add no visible defense.
5. Step 4: The sink is `shell_exec( 'ping  -c 4 ' . $target )` on line 14. The unsafe operation is executing a shell command constructed via string concatenation with user-controlled input, which can allow command injection through shell metacharacters.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec` executes the provided command string through the shell and does not automatically parameterize or sanitize command arguments. The additional context does not reveal any configured protection.
7. Step 6: The required authentication or privilege level is not visible in the provided context. The only visible reachability condition is `isset($_POST['Submit'])` on line 3. No authentication, authorization, or admin-only guard is shown.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete security impact is OS command injection leading to remote code execution with the privileges of the PHP/web server process. The attacker can potentially append shell operators and arbitrary commands to the intended `ping` invocation.
9. Step 8: The weakest link is the direct concatenation of untrusted request input into a shell command at line 14 without validation or escaping. No complete defense is visible in the original snippet or in the additional context, which is unavailable.
