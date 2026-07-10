# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/impossible.php:22

**Verdict:** FP · **Confidence:** High (0.88) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged `shell_exec()` sink is real, but the only visible path to line 22 is gated by numeric validation of exactly four octets on line 15 and reconstruction from those values and literal dots on line 17. Because shell metacharacters cannot pass that visible validation/reconstruction chain, the reported command-injection finding is not exploitable in the provided code.

## Data flow

source `$_REQUEST['ip']` (line 8) → `$target` assignment (line 8) → `stripslashes($target)` (line 9) → `explode('.', $target)` into `$octet` (line 12) → validation `is_numeric($octet[0..3])` and `sizeof($octet) == 4` (line 15) → reconstruction `$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3]` (line 17) → sink `$cmd = shell_exec( 'ping  ' . $target );` (line 22). Additional requested context for `checkToken` and `$html` was unavailable and adds no new data-flow step.

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 22 and its exact text is `$cmd = shell_exec( 'ping  ' . $target );`. The Semgrep-described construct is present on that line: `$target` is concatenated into a command string passed to `shell_exec()`. The function/context is listed as `<unknown>`; from the provided snippet it appears to be top-level PHP script code.
2. Step 1 / source: The potentially dangerous data originates from user-controlled request input: `$_REQUEST['ip']` assigned to `$target` on line 8. The code path is entered only if `isset($_POST['Submit'])` is true on line 3.
3. Step 2 / trace: Data flows from `$_REQUEST['ip']` on line 8 into `$target`; then `$target` is transformed by `stripslashes($target)` on line 9; then split into `$octet` with `explode('.', $target)` on line 12; then `$octet[0]` through `$octet[3]` are validated with `is_numeric()` and `sizeof($octet) == 4` on line 15; then `$target` is reconstructed from those four octets plus literal dots on line 17; then `$target` reaches the sink `shell_exec('ping  ' . $target)` on line 22.
4. Step 3 / validation and sanitization: `stripslashes()` on line 9 is not sufficient command-injection sanitization. However, line 15 validates that there are exactly four dot-separated parts and that each part is numeric, and line 17 reconstructs `$target` only from those validated parts and literal `.` separators. This is sufficient in the visible code to prevent shell metacharacters such as `;`, `&`, `|`, backticks, `$()`, `<`, and `>` from reaching the flagged shell command. The additional requested context for `function:checkToken` and `global:$html` was unavailable and does not change this assessment.
5. Step 4 / sink: The sink is line 22: `$cmd = shell_exec( 'ping  ' . $target );`. The dangerous operation is execution of a shell command constructed by string concatenation. There is also a sibling non-Windows sink on line 26, but the Semgrep finding specifically flags line 22.
6. Step 5 / framework or library protections: No automatic shell-command protection from a framework or library is visible. `checkToken()` on line 5 appears to be an anti-CSRF check, but its body was unavailable and it is not relevant shell escaping. The visible defense for the flagged sink is the explicit numeric validation and reconstruction on lines 15–17.
7. Step 6 / required privilege or authentication state: Not visible in provided context. The attacker must be able to submit a request with `$_POST['Submit']` set on line 3 and pass the token check on line 5, but whether that requires no authentication, a logged-in user, or an admin is not shown. The additional context did not provide caller or routing/authentication information.
8. Step 7 / security impact: If an attacker could inject shell metacharacters into `$target`, the impact would be OS command injection / remote code execution through `shell_exec()` on line 22. In the shown path, the numeric validation and reconstruction prevent such metacharacters from reaching the command.
9. Step 8 / weakest link: The weakest link is the use of `shell_exec()` with string concatenation on line 22 rather than an argument-safe API. However, for this specific flagged path, the defense visible on lines 15–17 is complete for command injection because `$target` is rebuilt from only numeric octets and literal dots before it reaches `shell_exec()`.
