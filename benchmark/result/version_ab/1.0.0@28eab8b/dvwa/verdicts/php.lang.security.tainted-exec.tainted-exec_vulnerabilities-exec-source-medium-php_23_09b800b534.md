# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is visible and directly executes a shell command containing request-controlled `$target`. The only visible defense is an incomplete blacklist that does not adequately neutralize shell metacharacters or enforce an IP allowlist, so an exploitable command-injection path is clearly present.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` → assigned to `$target` at line 5 → partial blacklist via `$substitutions` lines 8-11 → `str_replace(...)` on `$target` line 14 → concatenation into `'ping  -c 4 ' . $target` line 23 → `shell_exec()` command execution line 23

## Answers

1. Step 0 / flagged line location: The flagged line is present at vulnerabilities/exec/source/medium.php:23: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It is in the top-level script context shown as Function: `<unknown>`, not inside a named function in the provided snippet. The construct described by the rule is present: `shell_exec()` executes a non-constant command string concatenated with `$target`.
2. Step 1: The vulnerability class is command injection / OS command execution with tainted input. The rule is `php.lang.security.tainted-exec.tainted-exec`, and the sink is execution of a shell command with attacker-controlled data.
3. Step 2 / source: The potentially dangerous data originates from remote HTTP request input at line 5: `$target = $_REQUEST[ 'ip' ];`. `$_REQUEST['ip']` is attacker-controllable if this PHP script is web-accessible. The code path is entered when `$_POST['Submit']` is set on line 3.
4. Step 3 / trace: The data flow is visible entirely in the snippet: `$_REQUEST['ip']` is assigned to `$target` on line 5; blacklist entries are defined on lines 8-11; `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14; on the non-Windows branch, `$target` is concatenated into the command string and executed by `shell_exec()` on line 23.
5. Step 4 / validation or sanitization: A blacklist is applied at lines 8-14, removing only `&&` and `;`. This is not sufficient for command injection prevention because other shell metacharacters and command-substitution forms remain possible, such as `|`, `||`, backticks, `$()`, and newlines. No visible `escapeshellarg()`, strict IP allowlist validation, or safe argument-vector process API is used.
6. Step 5 / sink: The sink is `shell_exec()` at line 23. The dangerous operation is shell execution of a command constructed via string concatenation: `'ping  -c 4 ' . $target`.
7. Step 6 / framework or library protection: No automatic protection is visible. PHP `shell_exec()` does not parameterize or safely escape arguments. There is no visible framework layer, ORM, command wrapper, or configured sanitizer protecting this sink.
8. Step 7 / privileges or authentication: The visible gate is only `isset($_POST['Submit'])` on line 3. No authentication, authorization, role check, or admin-only guard is visible in the provided context. The scanner-reported source is remote request input, so external reachability is established for this tainted path.
9. Step 8 / impact: If an attacker controls `$_REQUEST['ip']`, they can inject shell syntax into the command executed at line 23, leading to remote command execution as the PHP/web server process user.
10. Step 9 / weakest link: The weakest link is the insufficient blacklist on lines 8-14. It attempts to remove only two command separators but leaves many shell execution mechanisms available before the tainted value reaches `shell_exec()` on line 23.
