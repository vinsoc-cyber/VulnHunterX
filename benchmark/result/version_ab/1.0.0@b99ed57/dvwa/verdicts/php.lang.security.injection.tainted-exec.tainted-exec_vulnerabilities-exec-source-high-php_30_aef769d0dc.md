# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is present and is a direct shell execution sink using request-controlled data. The only visible defense is incomplete blacklist replacement, with no strict allowlist validation or shell-safe escaping before `shell_exec()`.

## Data flow

`vulnerabilities/exec/source/high.php:5` `$_REQUEST['ip']` → `trim()` assigned to `$target` at line 5 → blacklist `str_replace()` at line 21 → concatenation into `'ping  -c 4 ' . $target` → `shell_exec()` at line 30

## Answers

1. Additional context that could refine reachability/authentication but is not necessary to identify the sink vulnerability: request `caller:<unknown>` or the enclosing route/script/controller that includes `vulnerabilities/exec/source/high.php`, and any global authentication/authorization gate if present. However, the provided snippet already shows the complete source-to-sink path for command execution.
2. Flagged line re-quoted exactly: line 30: `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It lives in the provided top-level PHP script context; the function is listed as `<unknown>` and no named function is visible.
3. Relevant chain with file/line references: user-controlled request data is read from `$_REQUEST['ip']` at `vulnerabilities/exec/source/high.php:5`; it is passed through `trim()` and assigned to `$target` at line 5; blacklist substitutions are defined at lines 8-18; `str_replace()` applies that blacklist to `$target` at line 21; the resulting `$target` is concatenated into a shell command and executed by `shell_exec()` at line 30.
4. There is visible sanitization at line 21, but it is blacklist-based and incomplete for shell command execution. No strict IP allowlist validation, `escapeshellarg()`, or non-shell execution API is visible before the sink at line 30.
5. The sink is `shell_exec()` at line 30. The dangerous operation is shell command execution using a string built from request-controlled data.
6. No automatic framework/library protection is visible. PHP `shell_exec()` does not automatically quote or parameterize shell arguments.
7. Reachability is gated by `isset($_POST['Submit'])` at line 3. Authentication state is not visible in the provided snippet, but an attacker who can submit that POST parameter and control `ip` can reach the path.
8. Concrete impact is command injection / remote code execution as the PHP/web-server process if shell metacharacters or command separators not removed by the blacklist are supplied.
