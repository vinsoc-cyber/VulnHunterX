# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line executes a non-constant shell command containing `$target`, which comes directly from `$_REQUEST['ip']` and is only passed through an insufficient blacklist removing `&&` and `;`. No visible validation, escaping, parameterization, or framework protection prevents command injection on the line 23 `shell_exec()` path.

## Data flow

vulnerabilities/exec/source/medium.php: $_REQUEST['ip'] user input (line 5) → assigned to $target (line 5) → partial blacklist definition removing only '&&' and ';' (lines 8-11) → str_replace transformation of $target (line 14) → non-Windows branch selected after php_uname check (lines 17-23) → $target concatenated into command string and executed by shell_exec (line 23) → command output appended to $html (line 27). Additional requested context for global:$html and enclosing route/script was unavailable and adds no defense or transformation.

## Answers

1. Step 0 / flagged line: line 23 is exactly `$cmd = shell_exec( 'ping  -c 4 ' . $target );`. The construct described by the rule is present on that line: `shell_exec()` executes a non-constant command string built by concatenating `$target`.
2. Step 1: The dangerous data originates from HTTP request input: `$target = $_REQUEST[ 'ip' ];` on line 5. `$_REQUEST` is user-controllable request data in PHP. The additional context for `global:$html` and the enclosing route/script is unavailable and does not change this source analysis.
3. Step 2: Data flow is: `$_REQUEST['ip']` is assigned to `$target` on line 5 → `$substitutions` blacklist is defined on lines 8-11 → `$target` is transformed by `str_replace(array_keys($substitutions), $substitutions, $target)` on line 14 → OS check occurs on line 17 → in the non-Windows branch, `$target` is concatenated into the shell command passed to `shell_exec()` on line 23. The new context provides no additional transformations.
4. Step 3: The only visible sanitization is the blacklist on lines 8-14, removing `&&` and `;`. This is insufficient for command injection because other shell metacharacters and command-substitution forms remain possible, including `|`, single `&`, backticks, `$()`, newlines, redirection, or attacker-controlled additional arguments. No strict IP allowlist validation and no `escapeshellarg()`/`escapeshellcmd()` use is visible. The additional context does not show any upstream validation.
5. Step 4: The sink is `shell_exec()` on line 23. The dangerous operation is execution of a shell command string assembled from a constant prefix, `'ping  -c 4 '`, and attacker-controlled `$target`.
6. Step 5: No framework or library automatic protection is visible. PHP `shell_exec()` does not parameterize shell arguments or automatically escape concatenated input. The requested additional context was unavailable, so it provides no evidence of framework-level protection.
7. Step 6: The only visible reachability guard is `if( isset( $_POST[ 'Submit' ] ) )` on line 3. No authentication, authorization, CSRF, or role check is visible. The precise authentication state required is not visible, but any user able to submit the relevant request parameters can reach the flagged code path.
8. Step 7: The concrete security impact is OS command injection, potentially arbitrary command execution/RCE as the PHP/web-server process user. This can lead to data theft, service compromise, privilege escalation depending on host permissions, or denial of service.
9. Step 8: The weakest link is the incomplete blacklist sanitization on lines 8-14 before passing request-controlled input to `shell_exec()` on line 23. The defense is not complete because it neither validates `$target` as an IP address nor safely escapes it as a shell argument.
