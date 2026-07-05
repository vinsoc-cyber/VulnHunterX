# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line 30 clearly executes a non-constant shell command containing request-derived `$target`. The only visible defenses are `trim()` and an incomplete blacklist, with no `escapeshellarg()` or strict IP validation before `shell_exec()`, and the additional context provided no contrary protection.

## Data flow

HTTP request input `$_REQUEST['ip']` at line 5 → `trim()` assignment to `$target` at line 5 → blacklist replacement via `str_replace(...)` at line 21 using substitutions from lines 8-18 → command construction by concatenating `$target` into `'ping  -c 4 ' . $target` at line 30 → execution by `shell_exec()` at line 30. Additional context for `global:$_REQUEST`, `global:$_POST`, enclosing script/route, and callers was unavailable and adds no visible sanitization or guard.

## Answers

1. Step 0: The exact flagged line is line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: a non-constant shell command is built by concatenating `$target` into the string passed to `shell_exec()`.
2. Step 1: The potentially dangerous data originates from HTTP request input on line 5: `$target = trim($_REQUEST[ 'ip' ]);`. `$_REQUEST['ip']` is user-controlled request data. The new context for `global:$_REQUEST` is unavailable and does not show any defense or change this source analysis.
3. Step 2: The data flow is: line 3 checks whether `$_POST['Submit']` is set; line 5 reads `$_REQUEST['ip']`, applies `trim()`, and assigns the result to `$target`; lines 8-18 define a blacklist substitution array; line 21 applies `str_replace(array_keys($substitutions), $substitutions, $target)` and reassigns `$target`; line 30 concatenates `$target` into the command string and passes it to `shell_exec()`.
4. Step 3: The visible transformations are `trim()` on line 5 and blacklist replacement on line 21 using the substitutions from lines 8-18. These are not sufficient command-injection defenses. `trim()` only removes leading/trailing whitespace, and the blacklist does not validate that `$target` is an IP address or safely quote it as a shell argument. No `escapeshellarg()` or strict allowlist validation is visible.
5. Step 4: The sink is line 30: `shell_exec( 'ping  -c 4 ' . $target );`. The unsafe operation is execution of a shell command constructed by string concatenation with request-derived data.
6. Step 5: No framework or library protection is visible. The additional requested context for globals, enclosing route/script, and callers is unavailable, so it provides no evidence of upstream validation. `shell_exec()` does not automatically escape shell arguments.
7. Step 6: The visible privilege/authentication requirement is only that the request sets `$_POST['Submit']` on line 3. No authentication, authorization, or admin-only guard is visible. The unavailable caller/router context does not add any such guard.
8. Step 7: If an attacker controls `$_REQUEST['ip']`, the impact is OS command injection, potentially remote command execution as the PHP/web-server process user. This can lead to data theft, file modification, lateral movement, or denial of service depending on deployment privileges.
9. Step 8: The weakest link is the incomplete blacklist-based filtering on line 21. It attempts to remove selected shell metacharacters but does not provide complete shell argument escaping or strict IP allowlist validation before the command execution on line 30.
