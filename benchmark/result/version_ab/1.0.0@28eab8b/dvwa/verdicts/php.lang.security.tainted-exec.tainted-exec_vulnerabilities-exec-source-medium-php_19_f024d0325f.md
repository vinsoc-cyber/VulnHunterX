# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.97) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line is visible and directly executes a shell command containing attacker-controlled request data. The only visible defense is an incomplete blacklist that does not provide adequate command-argument escaping or strict IP validation.

## Data flow

vulnerabilities/exec/source/medium.php:5 `$_REQUEST['ip']` user input → vulnerabilities/exec/source/medium.php:14 partial blacklist via `str_replace()` removing only `&&` and `;` → vulnerabilities/exec/source/medium.php:19 `$target` concatenated into `shell_exec('ping  ' . $target)`

## Answers

1. Requested additional context: No additional context is required to determine this finding because the remote source, transformation, and flagged sink are all visible in the provided snippet. If additional context were nevertheless collected, the only relevant item would be `caller:<unknown>` to identify routing/authentication context, but that would not change the command-injection data flow visible here.
2. Exact flagged line: line 19 reads `$cmd = shell_exec( 'ping  ' . $target );`. The function is shown as `<unknown>` / top-level PHP script context, not a named function.
3. Relevant chain with file:line references: vulnerabilities/exec/source/medium.php:5 reads attacker-controlled `$_REQUEST['ip']` into `$target`; vulnerabilities/exec/source/medium.php:8-11 defines a blacklist removing only `&&` and `;`; vulnerabilities/exec/source/medium.php:14 applies that incomplete blacklist using `str_replace()` and reassigns `$target`; vulnerabilities/exec/source/medium.php:19 concatenates `$target` into a shell command and executes it via `shell_exec()`.
4. There is no alloc/free/use lifetime chain relevant to this PHP command-injection finding. The relevant chain is tainted input → incomplete blacklist transformation → shell execution sink.
