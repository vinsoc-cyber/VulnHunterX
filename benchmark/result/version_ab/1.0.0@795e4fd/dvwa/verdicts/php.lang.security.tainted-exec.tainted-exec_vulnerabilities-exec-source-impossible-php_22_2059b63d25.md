# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/impossible.php:22

**Verdict:** FP · **Confidence:** Medium (0.8) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged `shell_exec()` at line 22 is a real command-execution sink using non-constant data, but the provided code shows a specific visible defense on the same path: the request value is split, each of exactly four octets is required to be numeric at line 15, and `$target` is reconstructed only from those values and literal dots at line 17. No additional context changed the analysis, and this visible validation/reconstruction prevents attacker-controlled shell metacharacters or arbitrary command text from reaching the sink.

## Data flow

vulnerabilities/exec/source/impossible.php:8 `$_REQUEST['ip']` user input → line 8 `$target` assignment → line 9 `stripslashes($target)` → line 12 `explode('.', $target)` into `$octet` → line 15 `is_numeric($octet[0..3]) && sizeof($octet) == 4` validation → line 17 `$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3]` reconstruction → line 22 `$cmd = shell_exec('ping  ' . $target)` sink

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/exec/source/impossible.php:22. Exact text: `$cmd = shell_exec( 'ping  ' . $target );`. This is top-level/unknown-function PHP code per the supplied context (`Function: <unknown>`). The rule-described construct is present: `shell_exec()` executes a non-constant command string containing `$target`.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP request data: `$_REQUEST['ip']` is assigned to `$target` at line 8. The additional context for `global:_REQUEST` is unavailable and does not change this conclusion.
3. Step 2: The visible trace is: `$_REQUEST['ip']` at line 8 → `$target` at line 8 → `stripslashes($target)` at line 9 → `explode('.', $target)` into `$octet` at line 12 → validation of `$octet[0]` through `$octet[3]` using `is_numeric()` and `sizeof($octet) == 4` at line 15 → reconstruction of `$target` from only those four octets and literal dots at line 17 → concatenation into `shell_exec()` at line 22.
4. Step 3: Validation/sanitization is visible. `stripslashes()` on line 9 is not sufficient command-injection sanitization. However, line 15 requires exactly four dot-separated components and requires each component to be numeric, and line 17 reconstructs `$target` only from those validated components plus literal `.` characters. For the specific command-injection issue, this prevents attacker-controlled shell metacharacters such as `;`, `&`, `|`, backticks, `$()`, or arbitrary command text from reaching the sink on this path. The additional context for `checkToken`, `$_REQUEST`, and `$_SESSION` was unavailable and does not reveal any contrary flow.
5. Step 4: The sink is `shell_exec()` at line 22. The dangerous operation is passing a shell command string, built by concatenating `'ping  '` and `$target`, to the operating-system shell.
6. Step 5: No framework or library automatic command-injection protection is visible. `checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php')` at line 5 appears to be CSRF-related, but its body is unavailable and it is not shown to perform shell escaping. PHP `shell_exec()` itself does not parameterize shell arguments.
7. Step 6: The privilege/authentication state is not visible in the provided code. The code path requires `isset($_POST['Submit'])` at line 3 and passing `checkToken()` at line 5, but whether the requester must be authenticated, unauthenticated, or admin-only is not shown.
8. Step 7: If unvalidated attacker-controlled command syntax reached `shell_exec()`, the impact would be OS command injection / RCE as the PHP process user. In the visible flagged path, the line 15 numeric validation and line 17 reconstruction prevent arbitrary shell syntax from being included in `$target`, so that impact is not clearly reachable from this code.
9. Step 8: The weakest link is the use of `shell_exec()` with string concatenation on line 22 rather than `escapeshellarg()` or a non-shell API. However, for this reported command-injection finding, the visible defense is complete enough on the shown path: line 15 constrains the input to exactly four numeric components and line 17 rebuilds the command argument from only those components and literal dots.
