# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not reveal any additional validation, authentication, or framework protection. The visible code shows request-controlled `$_REQUEST['ip']` flowing through an insufficient blacklist into `shell_exec()` on the flagged line 19, creating an exploitable OS command injection path.

## Data flow

HTTP request superglobal `$_REQUEST['ip']` (vulnerabilities/exec/source/medium.php:5; additional `global:$_REQUEST` context unavailable) → assigned to `$target` (line 5) → partial blacklist configuration `$substitutions` removes only `&&` and `;` (lines 8-11) → `str_replace(array_keys($substitutions), $substitutions, $target)` reassigns `$target` (line 14) → `$target` concatenated into command string and executed by `$cmd = shell_exec( 'ping  ' . $target );` (line 19). The route is gated only by `isset($_POST['Submit'])` (line 3; additional `global:$_POST` context unavailable).

## Answers

1. Step 0 / Locate flagged line: The flagged line 19 is exactly `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command string built by concatenating `$target`.
2. Function identification: The provided code context lists Function: `<unknown>`. The code appears to be top-level PHP script code, not inside a visible named function or method. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not identify an enclosing function.
3. Step 1: The potentially dangerous data originates from HTTP request input. Specifically, `$target = $_REQUEST[ 'ip' ];` on line 5 reads attacker-controllable request data. The additional context for `global:$_REQUEST` is unavailable and does not change this assessment; in PHP, `$_REQUEST` is a request superglobal.
4. Step 2: Data flow is: `$_REQUEST['ip']` at line 5 → assigned to `$target` at line 5 → blacklist array `$substitutions` defined at lines 8-11 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` at line 14 → transformed value reassigned to `$target` at line 14 → `$target` concatenated into command string in `shell_exec('ping  ' . $target)` at line 19. The code path is gated by `isset($_POST['Submit'])` at line 3, but the additional `global:$_POST` context is unavailable and shows no further validation.
5. Step 3: The only visible validation/sanitization is the blacklist replacement at lines 8-14, removing only `&&` and `;`. This is insufficient for command injection because other shell metacharacters and command execution mechanisms may remain, including `&`, `|`, backticks, `$()`, redirection operators, newline characters, and platform-specific shell syntax. No `escapeshellarg()`, `escapeshellcmd()`, strict IP allowlist validation, or safe process API with separated arguments is visible.
6. Step 4: The sink is `shell_exec()` at line 19. The unsafe operation is execution of a shell command string that includes request-derived `$target`. Because the shell interprets the final string, attacker-controlled shell syntax can alter the command.
7. Step 5: No framework or library automatic protection is visible. `shell_exec()` does not provide automatic argument escaping or parameterization. The additional context for `$_REQUEST` and `$_POST` is unavailable and provides no visible framework-level protection.
8. Step 6: The visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code. Therefore, based on the visible context, any user able to send a request reaching this script with `POST['Submit']` set and `REQUEST['ip']` controlled can trigger the path; exact authentication state is not visible.
9. Step 7: The concrete security impact is OS command injection, potentially leading to remote code execution as the PHP/web-server process user. Secondary impacts may include data theft, filesystem modification, lateral movement, and denial of service depending on deployment privileges.
10. Step 8: The weakest link is the incomplete blacklist at lines 8-14 combined with direct shell execution at line 19. The defense chain is not complete because request input reaches `shell_exec()` after only partial removal of two command separators, with no robust escaping or allowlist validation.
