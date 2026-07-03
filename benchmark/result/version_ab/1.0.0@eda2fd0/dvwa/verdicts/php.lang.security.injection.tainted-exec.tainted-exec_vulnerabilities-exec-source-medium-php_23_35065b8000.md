# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged CWE-78 construct is present: request-controlled `$_REQUEST['ip']` flows into `shell_exec()` on line 23 through only an incomplete blacklist on line 14. No adequate visible defense, such as strict IP validation or `escapeshellarg()`, prevents command injection on this path.

## Data flow

HTTP request parameter $_REQUEST['ip'] (line 5) → $target assignment (line 5) → blacklist definitions removing only '&&' and ';' (lines 8-11) → str_replace transformation and reassignment to $target (line 14) → OS branch (line 17) → command concatenation and shell_exec sink on Windows (line 19) or flagged *nix sink `$cmd = shell_exec( 'ping  -c 4 ' . $target );` (line 23) → command output appended to $html (line 27). Additional requested context for globals/wrappers/auth was unavailable and adds no visible sanitization or guard.

## Answers

1. Step 1: The dangerous data originates from user-controlled HTTP request input: `$_REQUEST['ip']` is assigned to `$target` on line 5. The additional context for `global:$html` and wrappers/auth checks is unavailable and does not change this source analysis.
2. Step 2: Data flow remains: request-controlled `$_REQUEST['ip']` on line 5 → assigned to `$target` on line 5 → blacklist substitutions are defined on lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → reassigned to `$target` on line 14 → concatenated into shell command strings on line 19 for Windows and line 23 for *nix → passed to `shell_exec()` on lines 19 and 23.
3. Step 3: The only visible sanitization is the blacklist replacement on line 14, using substitutions from lines 8-11 to remove `&&` and `;`. This is insufficient for command injection because other shell metacharacters and command-substitution mechanisms remain possible, such as `|`, single `&`, backticks, `$()`, newlines, redirection, or argument injection. No allowlist IP validation, `filter_var(..., FILTER_VALIDATE_IP)`, `escapeshellarg()`, or equivalent shell-safe escaping is visible. The unavailable additional context provides no visible additional defense.
4. Step 4: The sink is `shell_exec()` on the flagged line 23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The Windows branch also contains the same vulnerability pattern on line 19: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is executing a shell command string built by concatenating user-controlled input.
5. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically parameterize or escape shell command arguments. The additional requested wrapper/auth/global context was unavailable, so no framework-level protection can be cited from the provided code.
6. Step 6: Based on the visible code, the path is triggered when `isset($_POST['Submit'])` is true on line 3 and `$_REQUEST['ip']` is supplied on line 5. No authentication or authorization requirement is visible. The unavailable additional context does not establish any higher privilege requirement.
7. Step 7: If an attacker controls `$_REQUEST['ip']`, the concrete impact is OS command injection leading to remote command execution as the PHP/web-server process user, because the value reaches `shell_exec()` on line 23 and also line 19.
8. Step 8: The weakest link is the incomplete blacklist on lines 8-14. It attempts to remove only `&&` and `;`, but does not provide complete shell escaping or strict IP allowlist validation before the data reaches `shell_exec()` on line 23.
