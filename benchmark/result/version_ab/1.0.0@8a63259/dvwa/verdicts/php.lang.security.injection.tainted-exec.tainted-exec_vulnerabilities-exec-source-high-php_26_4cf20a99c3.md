# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not add any visible defense. The provided code clearly shows user-controlled request data from line 5 reaching `shell_exec` on line 26 after only incomplete blacklist filtering on lines 8-21, which is inadequate for preventing CWE-78 command injection.

## Data flow

vulnerabilities/exec/source/high.php:5 `$_REQUEST['ip']` → line 5 `trim(...)` assigns user input to `$target` → lines 8-18 blacklist substitutions are defined → line 21 `str_replace(...)` removes selected characters/sequences from `$target` → line 26 `$target` is concatenated into `'ping  ' . $target` and passed to `shell_exec(...)`

## Answers

1. Step 0: The exact flagged line is line 26: `$cmd = shell_exec( 'ping  ' . $target );`. The rule-described construct is present on that line: data in `$target` is concatenated into a command string passed to `shell_exec`, which executes a shell command. The enclosing function is still identified only as `Function: <unknown>`; the additional `function:<unknown>` context was unavailable.
2. Step 1: The dangerous data originates from user-controlled HTTP request input at line 5: `$target = trim($_REQUEST[ 'ip' ]);`. `$_REQUEST['ip']` is the ultimate visible source.
3. Step 2: Data flow through assignments and transformations: `$_REQUEST['ip']` is read at line 5, passed through `trim(...)`, and assigned to `$target`; a blacklist substitution array is defined on lines 8-18; `$target` is transformed with `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21; in the Windows branch beginning at line 24, `$target` is concatenated into `'ping  ' . $target` and executed by `shell_exec` on line 26. The additional requested contexts for `function:<unknown>`, `global:_REQUEST`, `global:_POST`, and `global:html` were unavailable and do not change this visible flow.
4. Step 3: The only visible validation/sanitization is blacklist replacement on lines 8-21. It removes some command metacharacters/sequences such as `||`, `&`, `;`, `| `, `-`, `$`, parentheses, and backticks, but this is not sufficient for OS command injection prevention. There is no visible strict IP allowlist validation, no `filter_var($target, FILTER_VALIDATE_IP)`, and no `escapeshellarg` or equivalent shell-safe argument escaping before line 26.
5. Step 4: The sink is `shell_exec` on line 26. The dangerous operation is execution of a shell command string built via concatenation of user-controlled `$target` into `ping`.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec` does not parameterize or safely quote arguments automatically. The additional context did not reveal any upstream middleware, framework validation, or automatic protection.
7. Step 6: The only visible trigger condition is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible. Based on the provided code, any requester able to send the relevant POST parameter and an `ip` request parameter can reach the path; whether the endpoint is otherwise access-controlled is not visible.
8. Step 7: If an attacker controls `$target`, the concrete security impact is OS command injection / remote code execution with the privileges of the PHP/web server process. The command output is captured in `$cmd` on line 26 and later added to `$html` on line 34.
9. Step 8: The weakest link is the incomplete blacklist sanitization on lines 8-21 followed by direct concatenation into `shell_exec` on line 26. The defense is not complete because robust command-argument handling would require strict allowlist validation for an IP address and/or correct shell escaping, neither of which is visible.
