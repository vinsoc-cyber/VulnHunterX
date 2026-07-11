# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is exactly present at line 19, and the visible data flow shows request-controlled `$_REQUEST['ip']` reaching `shell_exec()` after only an incomplete blacklist. The additional context is unavailable and does not provide any concrete defense, while the provided code itself clearly contains an exploitable command-injection path for any attacker who can reach this script.

## Data flow

user-controlled `$_REQUEST['ip']` source at vulnerabilities/exec/source/medium.php:5 → assigned to `$target` at line 5 → partial blacklist configuration at lines 8-11 → transformed by `str_replace()` at line 14, removing only `&&` and `;` → Windows branch condition at line 17 → sink `shell_exec('ping  ' . $target)` at line 19. Additional requested global/request/auth context was unavailable and adds no visible sanitization or guard.

## Answers

1. Step 0 / flagged line: The flagged line is present at line 19 and exactly reads `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command string formed by concatenating `$target`. The function is listed as `<unknown>`; based on the snippet, this appears to be top-level PHP script code in `vulnerabilities/exec/source/medium.php` rather than a named function.
2. Step 1: The dangerous data originates from user-controlled request input: `$target = $_REQUEST[ 'ip' ];` on line 5. The code path is entered when `$_POST['Submit']` is set on line 3. The additional requested context for request filtering/bootstrap and authentication/routing is unavailable, so it does not change this source assessment.
3. Step 2: Data flow is: request gate `isset($_POST['Submit'])` on line 3 → source `$_REQUEST['ip']` assigned to `$target` on line 5 → blacklist entries defined in `$substitutions` on lines 8-11 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → Windows OS branch selected on line 17 → `$target` concatenated into the shell command and executed by `shell_exec('ping  ' . $target)` on line 19.
4. Step 3: The only visible sanitization is a blacklist on lines 8-14 that removes `&&` and `;`. This is insufficient for command injection because it does not validate that the input is an IP address and does not escape it with `escapeshellarg()` or equivalent. Other shell metacharacters/operators may remain usable depending on the shell/platform. The additional context did not reveal any global filtering or framework protection.
5. Step 4: The sink is line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The unsafe operation is shell command execution using a command string built with user-controlled input.
6. Step 5: No automatic framework/library protection is visible. `shell_exec()` does not parameterize or escape shell arguments automatically. The requested global request filtering/bootstrap and authentication/routing contexts are unavailable, so there is no visible framework-level defense that would prevent exploitation.
7. Step 6: The visible trigger condition is that an attacker can send a request with `$_POST['Submit']` set on line 3 and control `$_REQUEST['ip']` on line 5. No authentication or authorization checks are visible. The additional authentication/routing context is unavailable, so the exact privilege level is not visible; however, the vulnerability exists for any user who can reach this script path.
8. Step 7: If an attacker controls `$target`, the concrete impact is OS command injection through `shell_exec()`, potentially leading to remote code execution as the web server user, data theft, server compromise, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist on lines 8-14 combined with direct concatenation into `shell_exec()` on line 19. The defense chain is not complete because there is no visible allowlist IP validation or shell argument escaping.
