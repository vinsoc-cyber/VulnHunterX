# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context does not change the prior analysis because `global:$html` is unavailable and no additional validation or protection is shown. The flagged line is a real shell-execution sink, and user-controlled `$_REQUEST['ip']` reaches it after only incomplete blacklist filtering, with no visible strict validation or safe shell escaping.

## Data flow

`vulnerabilities/exec/source/high.php:5` source `$_REQUEST['ip']` → line 5 `trim()` assigned to `$target` → lines 8-18 blacklist definition → line 21 partial blacklist replacement with `str_replace(...)` → line 30 sink `shell_exec('ping  -c 4 ' . $target)` → line 34 command output appended to `$html`; additional `global:$html` context is unavailable and adds no visible defense

## Answers

1. Step 0 / flagged line location: The flagged line is present at `vulnerabilities/exec/source/high.php:30` and its exact text is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. This is in function/context `<unknown>`; the snippet appears to be top-level PHP code rather than a named function. The construct described by the rule is present: user-influenced data is concatenated into a command string passed to `shell_exec()`.
2. Step 1: The potentially dangerous data originates from HTTP request input: `$_REQUEST['ip']` on line 5. The branch is entered when `$_POST['Submit']` is set on line 3.
3. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` assigned to `$target` on line 5 → `$substitutions` blacklist defined on lines 8-18 → `$target` rewritten by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → `$target` concatenated into the shell command at line 30. The additional `global:$html` context is unavailable and does not add any visible transformation or defense.
4. Step 3: The visible transformations are `trim()` on line 5 and blacklist-based `str_replace()` on line 21. This is not sufficient for command injection prevention because it does not enforce a strict IP address allowlist and does not use `escapeshellarg()` or an argument-vector API. The blacklist removes some metacharacters listed on lines 9-18, but blacklist filtering is incomplete for shell command construction.
5. Step 4: The sink is `shell_exec()` on line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The dangerous operation is execution of a shell command string containing attacker-controlled request data.
6. Step 5: No automatic framework or library protection is visible. `shell_exec()` executes a shell command string and does not automatically parameterize or safely quote `$target`. No visible ORM, template auto-escaping, command argument separation, `escapeshellarg()`, or strict IP validation is present. The newly provided `global:$html` context is unavailable and does not show any protection.
7. Step 6: Based on the visible code, an attacker needs only the ability to submit a request where `$_POST['Submit']` is set and `$_REQUEST['ip']` is controlled, as shown on lines 3 and 5. No authentication, authorization, or admin-only check is visible.
8. Step 7: The concrete security impact is command injection leading to remote code execution as the PHP/web-server user. The command output is stored in `$cmd` on line 30 and appended to `$html` on line 34, potentially exposing command output to the user.
9. Step 8: The weakest link is the blacklist sanitizer on line 21. It attempts to remove selected shell metacharacters but fails to provide a complete defense; the safe defense would be strict validation of `$target` as an IP address and/or safe shell argument escaping before `shell_exec()`.
