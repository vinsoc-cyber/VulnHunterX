# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and provides no visible upstream defense. The shown code clearly lets request-controlled `$_REQUEST['ip']` reach `shell_exec()` at line 26 after only incomplete blacklist replacement, making command injection exploitable on the flagged path.

## Data flow

vulnerabilities/exec/source/high.php:3 request-controlled `$_POST['Submit']` gates execution → line 5 user-controlled `$_REQUEST['ip']` → line 5 `trim()` into `$target` → lines 8-18 blacklist definition → line 21 incomplete `str_replace()` blacklist transformation → line 26 `$cmd = shell_exec( 'ping  ' . $target );`

## Answers

1. Step 0 / flagged-line location: The flagged line is present at line 26 and is exactly `$cmd = shell_exec( 'ping  ' . $target );`. It lives in function `<unknown>` / apparent top-level PHP script context, since no named enclosing function is shown. The rule-described construct is present on that line: `shell_exec()` executes a non-constant command built by concatenating `$target`.
2. Step 1: The dangerous data originates from HTTP request input: `$_REQUEST['ip']` on line 5. The code path is gated by `isset($_POST['Submit'])` on line 3, also request-controlled. The additional requested contexts for `global:$_REQUEST` and `global:$_POST` were unavailable and do not change this conclusion.
3. Step 2: Data flow is: `$_REQUEST['ip']` is read and passed to `trim()` on line 5; the result is assigned to `$target` on line 5; a blacklist array `$substitutions` is defined on lines 8-18; `$target` is transformed with `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21; the transformed `$target` is concatenated into the command string passed to `shell_exec()` at line 26 in the Windows branch. There is also a sibling non-Windows sink at line 30, but the flagged sink is line 26.
4. Step 3: The only visible sanitization is blacklist replacement on line 21 using substitutions from lines 8-18. This is insufficient for command injection because it does not perform strict IP-address validation and does not use `escapeshellarg()`. It also leaves bypassable shell syntax, such as a bare `|` not followed by a space, because only `'||'` and `'| '` are removed on lines 9 and 12.
5. Step 4: The sink is `shell_exec('ping  ' . $target)` on line 26. The unsafe operation is executing a shell command string containing request-controlled data, which can allow shell command injection.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not automatically escape shell arguments, and the additional context provided for globals and the enclosing route/controller was unavailable, so it adds no visible protection.
7. Step 6: Based on the provided code, an attacker needs the ability to send a request with `$_POST['Submit']` set on line 3 and an `ip` parameter in `$_REQUEST` on line 5. No authentication or authorization checks are visible, so the required privilege level is not constrained in the shown code.
8. Step 7: The concrete security impact is command injection leading to command execution as the PHP/web-server process user. An attacker could execute OS commands, read accessible files, modify accessible data, or cause denial of service.
9. Step 8: The weakest link is the incomplete blacklist sanitization on lines 8-21. It is not a complete defense because it attempts to remove selected metacharacters instead of enforcing a strict IP allowlist or safely escaping the shell argument before line 26.
