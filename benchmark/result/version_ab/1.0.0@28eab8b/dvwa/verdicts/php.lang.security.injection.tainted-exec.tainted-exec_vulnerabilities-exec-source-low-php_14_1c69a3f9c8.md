# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.98) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

Although additional context was requested, the flagged line is visible and the complete vulnerable path from remote request input to PHP's built-in shell execution sink is present in the snippet. No visible defense exists on the flagged path, so marking this as Needs More Data would contradict the provided evidence and the verdict rules.

## Data flow

HTTP request parameter `$_REQUEST['ip']` (`vulnerabilities/exec/source/low.php:5`) → `$target` (`vulnerabilities/exec/source/low.php:5`) → concatenated into `'ping  -c 4 ' . $target` (`vulnerabilities/exec/source/low.php:14`) → executed by `shell_exec(...)` (`vulnerabilities/exec/source/low.php:14`)

## Answers

1. Additional context request considered: `caller:<unknown>` is unavailable per provided pre-fetched context, and no named function, struct, or global variable is involved in the visible data flow. The sink is PHP built-in `shell_exec`, so no callee implementation is needed.
2. Exact flagged line: line 14 is `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. It lives at top-level PHP script scope / function `<unknown>`, not inside a visible named function.
3. Relevant chain with file:line references: `vulnerabilities/exec/source/low.php:3` checks `isset($_POST['Submit'])`; `vulnerabilities/exec/source/low.php:5` reads attacker-controlled `$_REQUEST['ip']` into `$target`; `vulnerabilities/exec/source/low.php:14` concatenates `$target` into a shell command and executes it via `shell_exec`.
4. There is no alloc/free/use lifetime chain relevant to this PHP command-injection finding. The relevant chain is tainted request input → string concatenation → shell execution.
5. No validation, sanitization, allowlist, `escapeshellarg()`, `escapeshellcmd()`, or IP validation is visible between line 5 and line 14.
6. The code path is reachable when `$_POST['Submit']` is set on line 3. The scanner-reported source is remote HTTP request input, so caller context is not needed to establish taint-source reachability.
7. The dangerous operation is shell command execution on line 14. Because `$target` is concatenated into the shell command, shell metacharacters in `$_REQUEST['ip']` can alter the executed command.
8. No framework or library protection is visible. PHP `shell_exec` does not automatically escape command arguments.
