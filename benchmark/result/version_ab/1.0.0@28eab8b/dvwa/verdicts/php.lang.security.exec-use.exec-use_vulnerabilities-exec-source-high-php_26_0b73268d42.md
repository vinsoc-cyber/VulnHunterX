# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is visible and executes a non-constant shell command containing request-derived `$target`. The only visible defenses are `trim()` and an incomplete blacklist, which do not adequately prevent shell command injection before `shell_exec()`.

## Data flow

HTTP request source `$_REQUEST['ip']` (line 5) → `trim()` (line 5) → `$target` assignment (line 5) → blacklist replacement via `str_replace()` using `$substitutions` from lines 8-18 (line 21) → `$target` concatenated into `'ping  ' . $target` (line 26) → `shell_exec()` command execution sink (line 26). Additional context for `global:$target` and `global:$substitutions` was unavailable and adds no visible sanitization or guard.

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 26 and its exact text is `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present: `shell_exec()` executes a non-constant command string built by concatenating user-influenced `$target`.
2. Step 1: The potentially dangerous data originates from HTTP request input: `$_REQUEST['ip']` is read on line 5 and assigned to `$target` after `trim()`. In PHP, `$_REQUEST` is externally controllable request data.
3. Step 2: The data flow is: `$_REQUEST['ip']` on line 5 → `trim($_REQUEST['ip'])` on line 5 → assignment to `$target` on line 5 → `$target` is processed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 using the blacklist array defined on lines 8-18 → reassigned to `$target` on line 21 → concatenated into the command string in `shell_exec('ping  ' . $target)` on line 26.
4. Step 3: There is attempted sanitization, but it is insufficient for OS command injection. `trim()` on line 5 only removes leading/trailing whitespace. The blacklist on lines 8-18 removes selected substrings/characters such as `||`, `&`, `;`, `| `, `-`, `$`, `(`, `)`, and backticks, and is applied on line 21. This does not enforce that `$target` is an IP address or safe hostname, does not use `escapeshellarg()` / `escapeshellcmd()`, and does not remove all shell-control syntax, for example a bare pipe `|` not followed by a space.
5. Step 4: The sink is line 26: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is execution of a shell command assembled via string concatenation with request-derived data.
6. Step 5: No framework or library automatic protection is visible. `shell_exec()` does not automatically parameterize or safely quote arguments, and no upstream validation framework is shown. The additional requested global context for `$target` and `$substitutions` is unavailable and does not provide any visible defense.
7. Step 6: The visible trigger is `if( isset( $_POST['Submit'] ) )` on line 3. No authentication or authorization check is visible in the provided code, so the visible path appears reachable by any HTTP requester able to submit the relevant POST parameter. The pre-fetched caller context is unavailable, but the request source itself establishes external reachability.
8. Step 7: The concrete security impact is OS command injection, potentially remote code execution as the web-server/PHP process user. For example, because `|` is not fully removed, request input can alter the shell pipeline and execute another command after `ping`.
9. Step 8: The weakest link is the blacklist-based defense on lines 8-21. It is incomplete and non-allowlist-based, and the resulting `$target` is still concatenated directly into `shell_exec()` on line 26.
