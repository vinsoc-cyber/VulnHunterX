# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged sink is present exactly at line 19 and directly executes a command string containing user-controlled request data. The visible blacklist removes only two tokens and is not an adequate defense against command injection.

## Data flow

HTTP request parameter $_REQUEST['ip'] (vulnerabilities/exec/source/medium.php:5) → assigned to $target (line 5) → partial blacklist via str_replace removing only '&&' and ';' (lines 8-14) → concatenated into shell_exec('ping  ' . $target) (line 19)

## Answers

1. The exact flagged line is line 19: `$cmd = shell_exec( 'ping  ' . $target );`. It lives in the provided top-level PHP script context; the function is shown as `<unknown>`, and no named function/method encloses it in the snippet.
2. The dangerous data originates from HTTP request input: `$_REQUEST['ip']` is assigned to `$target` on line 5, under the condition `isset($_POST['Submit'])` on line 3.
3. The data chain is: `$_REQUEST['ip']` at `vulnerabilities/exec/source/medium.php:5` → `$target` assignment at line 5 → `$target` is passed through `str_replace(array_keys($substitutions), $substitutions, $target)` at line 14 using a blacklist defined at lines 8-11 → `$target` is concatenated into the command string at the sink `shell_exec('ping  ' . $target)` at line 19.
4. The only visible sanitization is the blacklist at lines 8-14, which removes `&&` and `;`. This is insufficient for shell command injection because other shell metacharacters and command-substitution mechanisms remain possible. No strict IP validation or `escapeshellarg()`/`escapeshellcmd()` is visible.
5. The sink is `shell_exec()` at line 19. The operation is dangerous because it executes a shell command constructed by concatenating user-controlled input into a non-constant command string.
6. No framework or library protection is visible in the provided code. PHP `shell_exec()` does not automatically parameterize or safely escape concatenated shell arguments.
7. The authentication/privilege requirement is not fully visible. The only visible gate is `isset($_POST['Submit'])` at line 3. Additional routing, authentication, or include context is not shown.
8. Relevant chain with concrete file/line references: source `vulnerabilities/exec/source/medium.php:5` → blacklist transform `vulnerabilities/exec/source/medium.php:8-14` → Windows branch sink `vulnerabilities/exec/source/medium.php:19`. The analogous non-Windows branch sink is line 23, but the reported finding is specifically line 19.
