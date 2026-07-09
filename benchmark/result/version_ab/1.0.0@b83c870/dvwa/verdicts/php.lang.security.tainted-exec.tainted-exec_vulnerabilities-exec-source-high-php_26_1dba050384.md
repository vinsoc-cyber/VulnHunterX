# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and therefore does not change the visible evidence: user-controlled `$_REQUEST['ip']` reaches `shell_exec()` at line 26 after only incomplete blacklist filtering. There is no visible strict IP validation, `escapeshellarg()`, or shell-free command execution, so the flagged sink is exploitable as command injection.

## Data flow

HTTP request input `$_REQUEST['ip']` (vulnerabilities/exec/source/high.php:5) → `trim($_REQUEST['ip'])` assigned to `$target` (line 5) → blacklist array defined (lines 8-18) → `$target = str_replace(array_keys($substitutions), $substitutions, $target)` (line 21) → Windows branch condition `stristr(php_uname('s'), 'Windows NT')` (line 24) → `$target` concatenated into `'ping  ' . $target` and passed to `shell_exec()` (line 26)

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/high.php:26 and is exactly `$cmd = shell_exec( 'ping  ' . $target );`. The rule-described construct is present on that line: a non-constant shell command is built by concatenating `$target` and passed to `shell_exec()`.
2. Step 1 source: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` at vulnerabilities/exec/source/high.php:5. The path is gated by `isset($_POST['Submit'])` at line 3, but the `ip` value itself comes from `$_REQUEST`, which can include user-controlled request parameters.
3. Step 2 trace: `$_REQUEST['ip']` is read at line 5, passed to `trim()`, and assigned to `$target` at line 5. A blacklist substitution array is defined at lines 8-18. `$target` is then transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` at line 21. The Windows branch is selected by `stristr(php_uname('s'), 'Windows NT')` at line 24. In that branch, `$target` is concatenated into `'ping  ' . $target` and executed by `shell_exec()` at line 26.
4. Step 3 validation/sanitization: The visible transformations are `trim()` at line 5 and blacklist replacement at line 21 using substitutions from lines 8-18. This is not sufficient for command injection prevention. The code does not use `escapeshellarg()`, does not use a shell-free process API, and does not validate `$target` as an IP address with an allowlist or IP parser. The new requested contexts for `function:<unknown>` and `global:$_REQUEST` were unavailable, so they do not add any visible defense or change this answer.
5. Step 4 sink: The sink is `shell_exec()` at vulnerabilities/exec/source/high.php:26. The unsafe operation is executing an OS shell command string that includes user-derived `$target`.
6. Step 5 framework/library protections: No framework or library protection is visible. `shell_exec()` does not automatically escape command arguments. The additional context supplied was unavailable and does not show any upstream validation, escaping, authentication, or routing protection.
7. Step 6 privilege/authentication state: The only visible trigger condition is `isset($_POST['Submit'])` at line 3. No authentication, authorization, role check, CSRF check, or admin-only guard is visible in the provided code or additional context. Therefore, based on visible evidence, an attacker only needs the ability to send a request that sets `Submit` and `ip`.
8. Step 7 impact: If an attacker controls `$target`, the impact is OS command injection, potentially remote code execution as the PHP/web-server process user. This can lead to data theft, file modification, service compromise, or denial of service depending on process privileges.
9. Step 8 weakest link: The weakest link is the incomplete blacklist filtering on lines 8-21 followed by direct command execution on line 26. The defense chain is incomplete because the code relies on removing selected characters rather than using strict validation or safe shell argument escaping.
