# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 19 is a real command-execution sink, and user-controlled `$_REQUEST['ip']` reaches it after only inadequate blacklist filtering. Because no complete validation, escaping, or safe argument separation is visible, the command injection path is clearly exploitable.

## Data flow

HTTP request input `$_REQUEST['ip']` (line 5) → assigned to `$target` (line 5) → partial blacklist substitution via `str_replace()` removing only `&&` and `;` (lines 8-14) → concatenated into shell command string `'ping  ' . $target` (line 19) → executed by `shell_exec()` (line 19)

## Answers

1. Step 0 / flagged line: The exact flagged line is line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command created by concatenating `$target` into the command string.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST` can contain externally supplied GET, POST, or cookie parameters.
3. Step 2: The data flow is: `$_REQUEST['ip']` is assigned to `$target` at line 5; blacklist replacement rules are defined at lines 8-11; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` at line 14; the transformed `$target` is concatenated into a shell command and executed by `shell_exec()` at line 19 in the Windows branch. A similar non-Windows sink appears at line 23, but the Semgrep finding specifically flags line 19.
4. Step 3: There is partial blacklist sanitization at lines 8-14, removing only `&&` and `;`. This is insufficient for command injection because other shell metacharacters and command-composition mechanisms remain possible, including `&`, `|`, newlines, redirection, backticks, `$()`, and platform-specific shell syntax. No whitelist IP validation, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, `escapeshellcmd()`, or safe process argument API is visible.
5. Step 4: The sink is `shell_exec()` at line 19. The unsafe operation is execution of a shell command string built with attacker-controlled input: `'ping  ' . $target`.
6. Step 5: No framework or library-level automatic protection is visible. PHP `shell_exec()` does not parameterize arguments or automatically escape untrusted shell input.
7. Step 6: The only visible gate is `isset($_POST['Submit'])` at line 3. No authentication or authorization check is shown, so based on the provided context an attacker only needs the ability to send an HTTP request with `Submit` set and control `ip`.
8. Step 7: The concrete security impact is OS command injection, potentially resulting in remote command execution as the PHP/web-server process user, with possible data theft, service compromise, lateral movement, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist at lines 8-14. It attempts to remove only two command separators before passing the value to `shell_exec()` at line 19, leaving many command-injection vectors available.
