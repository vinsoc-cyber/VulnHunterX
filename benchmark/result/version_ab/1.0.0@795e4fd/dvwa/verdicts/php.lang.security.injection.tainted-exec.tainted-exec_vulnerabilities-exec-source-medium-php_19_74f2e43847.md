# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and directly executes a shell command containing request-controlled `$target`. The only visible defense is an insufficient blacklist that removes two tokens, with no adequate shell escaping or IP allowlist validation shown in either the original snippet or the additional context.

## Data flow

HTTP request input `$_REQUEST['ip']` (`vulnerabilities/exec/source/medium.php:5`) → assigned to `$target` (`line 5`) → partial blacklist substitution removes only `&&` and `;` (`lines 8-14`) → OS branch check via `stristr(php_uname('s'), 'Windows NT')` (`line 17`) → command execution sink `shell_exec('ping  ' . $target)` (`line 19`); sibling non-Windows sink is `shell_exec('ping  -c 4 ' . $target)` (`line 23`)

## Answers

1. Step 0 / Flagged line: The flagged line 19 is present and is exactly `$cmd = shell_exec( 'ping  ' . $target );`. It contains the rule-described construct: a value derived from request input is concatenated into a command string passed to PHP `shell_exec()`.
2. Step 1 / Source: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` assigned to `$target` on line 5. The code path is gated by `isset($_POST['Submit'])` on line 3. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable, but in PHP these are request superglobals, and nothing in the additional context shows a constraint or sanitizer.
3. Step 2 / Trace: `$_REQUEST['ip']` on line 5 → assigned to `$target` on line 5 → `$substitutions` blacklist defined on lines 8-11 → `$target` transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → `$target` concatenated into the Windows command executed by `shell_exec('ping  ' . $target)` on line 19. The non-Windows sibling path similarly executes `shell_exec('ping  -c 4 ' . $target)` on line 23.
4. Step 3 / Validation, sanitization, or encoding: The only visible sanitization is blacklist removal on line 14, using substitutions defined on lines 8-11 to remove `&&` and `;`. This is insufficient for OS command injection because many shell metacharacters and command-substitution mechanisms remain possible, such as `|`, single `&`, backticks, `$()`, redirection, newlines, or platform-specific shell syntax. No strict IP validation such as `filter_var($target, FILTER_VALIDATE_IP)` and no shell escaping such as `escapeshellarg()` is visible.
5. Step 4 / Sink: The sink is `shell_exec()` on line 19, where `$target` is concatenated into the shell command. The dangerous operation is executing a shell command string that includes user-controlled data. The additional context does not provide any alternative implementation or wrapper; this is PHP’s built-in `shell_exec()`.
6. Step 5 / Framework or library protections: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically parameterize or escape command arguments. The additional requested context was unavailable and does not reveal any upstream middleware, framework validation, or configuration that would protect this sink.
7. Step 6 / Required privilege or authentication state: Based on the visible code, an attacker needs the ability to send a request with `$_POST['Submit']` set, per line 3, and control `$_REQUEST['ip']`, per line 5. No authentication or authorization check is visible in the provided context or additional context, so the visible evidence supports reachability by any requester who can access this script.
8. Step 7 / Security impact: If an attacker controls `$_REQUEST['ip']`, they can inject additional shell syntax into the command executed on line 19. The impact is arbitrary OS command execution / remote code execution with the privileges of the PHP web server process.
9. Step 8 / Weakest link: The weakest link is the incomplete blacklist sanitization on lines 8-14 before direct command execution on line 19. The defense is incomplete because it removes only `&&` and `;`, while the code still concatenates user-controlled input into a shell command without strict allowlist validation or shell-argument escaping.
10. Effect of additional context: The new context does not change the previous technical analysis. `global:$_REQUEST`, `global:$_POST`, and `function:<unknown>` are unavailable/out-of-snippet and provide no visible sanitizer, validator, authentication check, or other defense that would prevent exploitation.
