# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line is line 26: `$cmd = shell_exec( 'ping  ' . $target );`, in top-level PHP code/function `<unknown>`. User-controlled request data reaches this shell execution sink after only incomplete blacklist filtering; a bare `|` is not removed by the visible substitutions, and no strict IP validation or shell escaping is present.

## Data flow

HTTP request source `$_REQUEST['ip']` (line 5) → `trim()` and assignment to `$target` (line 5) → blacklist replacement with `str_replace(...)` (line 21) using `$substitutions` (lines 8-18) → command execution sink `shell_exec('ping  ' . $target)` (line 26, flagged Windows branch) and `shell_exec('ping  -c 4 ' . $target)` (line 30, Unix branch). Additional context for `global:$html`, `global:$_REQUEST`, and `global:$_POST` was unavailable and adds no visible defense.

## Answers

1. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` is read on line 5 after `$_POST['Submit']` is checked on line 3. The additional context for `global:$_REQUEST` and `global:$_POST` is unavailable and does not change this.
2. Step 2: Data flow is: `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` on line 5 → assignment to `$target` on line 5 → blacklist array `$substitutions` defined on lines 8-18 → `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → concatenation into `shell_exec('ping  ' . $target)` on line 26 for Windows or `shell_exec('ping  -c 4 ' . $target)` on line 30 for Unix-like systems.
3. Step 3: Sanitization is present but insufficient. `trim()` on line 5 only removes leading/trailing whitespace. `str_replace()` on line 21 removes a blacklist of characters/sequences from lines 8-18, but it does not strictly validate that `$target` is an IP address and does not use `escapeshellarg()`. The blacklist is incomplete for shell execution; for example, a single pipe character `|` not followed by a space is not removed because the blacklist contains `'||'` and `'| '` but not bare `'|'` on lines 9 and 12.
4. Step 4: The sinks are `shell_exec()` on line 26 and line 30. The unsafe operation is executing a shell command built by string concatenation with attacker-controlled `$target`.
5. Step 5: No framework or library automatic protection is visible. The additional requested global context is unavailable and shows no protection. PHP `shell_exec()` does not automatically parameterize or escape shell arguments.
6. Step 6: The code path requires `$_POST['Submit']` to be set on line 3. No authentication or authorization requirement is visible in the provided context, so the exact privilege level is not visible; any user able to send the relevant POST/request parameters can trigger the shown path.
7. Step 7: The concrete security impact is remote command execution as the PHP/web-server process user, because attacker-controlled input can alter the shell command executed by `shell_exec()` on line 26 or line 30.
8. Step 8: The weakest link is the incomplete blacklist sanitization on line 21 using substitutions from lines 8-18. It is not a complete defense because it neither enforces an IP-address allowlist nor safely escapes the shell argument before execution.
