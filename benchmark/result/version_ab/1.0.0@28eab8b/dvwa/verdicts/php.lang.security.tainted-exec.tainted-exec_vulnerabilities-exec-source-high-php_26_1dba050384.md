# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is visible at line 26 and attacker-controlled request data from line 5 reaches it after only incomplete blacklist filtering. Because the command is constructed by concatenation and executed via `shell_exec()` with no adequate escaping or strict validation, this is an exploitable command injection/RCE issue on the flagged Windows path.

## Data flow

vulnerabilities/exec/source/high.php: HTTP request source `$_REQUEST['ip']` (line 5) → `trim()` into `$target` (line 5) → incomplete blacklist replacement via `str_replace()` (line 21, substitutions lines 8-18) → OS check selects Windows branch (line 24) → command execution sink `shell_exec('ping  ' . $target)` (line 26). Additional requested globals `$_REQUEST`, `$_POST`, and `$html` were unavailable/out-of-snippet and add no visible defense.

## Answers

1. Step 0 / flagged line location: The flagged line is present at vulnerabilities/exec/source/high.php:26 and its exact text is `$cmd = shell_exec( 'ping  ' . $target );`. The construct described by the rule is present on that line: a non-constant shell command is built by concatenating `$target` into a string passed to `shell_exec()`. It lives in Function `<unknown>` per the metadata; in the snippet it appears to be top-level PHP code inside the `if (isset($_POST['Submit']))` block starting at line 3.
2. Step 1: The potentially dangerous data originates from HTTP request input: `$_REQUEST['ip']` on line 5. This is user-controlled request data. The added context for `global:$_REQUEST` and `global:$_POST` is unavailable/out-of-snippet, so it does not show any additional constraint or defense.
3. Step 2: Data flow trace: `$_REQUEST['ip']` is read on line 5 → passed through `trim()` and assigned to `$target` on line 5 → substitution rules are defined in `$substitutions` on lines 8-18 → `$target` is rewritten with `str_replace(array_keys($substitutions), $substitutions, $target)` on line 21 → the Windows branch is selected by `stristr(php_uname('s'), 'Windows NT')` on line 24 → `$target` is concatenated into the command string passed to `shell_exec()` on line 26.
4. Step 3: There is some filtering, but it is not sufficient. `trim()` on line 5 only removes surrounding whitespace. The blacklist replacement on line 21 removes selected characters/sequences from lines 8-18, including `||`, `&`, `;`, `| `, `-`, `$`, parentheses, and backticks. This is incomplete for command execution. For example, line 12 removes only pipe followed by a space (`'| '`), not a bare pipe (`'|'`), so input such as `127.0.0.1|whoami` can still alter command execution on the Windows `shell_exec()` path. There is no visible `escapeshellarg()`, `escapeshellcmd()`, or strict IP allowlist validation.
5. Step 4: The sink is `shell_exec()` at line 26: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is OS command execution using a string built from attacker-controlled input.
6. Step 5: No framework or library automatic protection is visible. The newly provided global context is unavailable and does not show upstream validation, routing protections, or framework-level sanitization. PHP `shell_exec()` does not automatically parameterize or safely quote shell arguments.
7. Step 6: The visible trigger is `isset($_POST['Submit'])` on line 3. No authentication or authorization check is visible in the provided code. Based on the visible request source, an attacker who can submit the relevant HTTP request parameters can reach this path; any additional authentication state is not visible in provided context.
8. Step 7: The concrete security impact is command injection leading to remote command execution as the web server/PHP process user. Depending on host privileges, this can enable data theft, service compromise, privilege escalation paths, or denial of service.
9. Step 8: The weakest link is the blacklist-based filtering on lines 8-21. It is incomplete and context-unsafe for shell command construction. A complete defense would require strict validation of `$target` as an IP address/hostname and/or safe shell argument escaping such as `escapeshellarg()` before passing it to `shell_exec()`.
