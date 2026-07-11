# php.lang.security.exec-use.exec-use @ vulnerabilities/api/src/HealthController.php:88

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line in `checkConnectivity` executes a shell command built by concatenating `$target`, which is sourced from the raw HTTP request body. The provided code shows no validation, allowlisting, or shell escaping before `exec()`, so the flagged sink is clearly exploitable as OS command injection if the method is reachable.

## Data flow

vulnerabilities/api/src/HealthController.php:84 file_get_contents('php://input') → vulnerabilities/api/src/HealthController.php:84 json_decode(..., TRUE) and array cast into $input → vulnerabilities/api/src/HealthController.php:85 key-existence check only → vulnerabilities/api/src/HealthController.php:86 $target = $input['target'] → vulnerabilities/api/src/HealthController.php:88 exec("ping -c 4 " . $target, ...)

## Answers

1. Flagged line located and confirmed: line 88 in function `checkConnectivity` is exactly `exec ("ping -c 4 " . $target, $output, $ret_var);`. This is a PHP `exec()` call using a non-constant command string constructed with `$target`, matching the rule's described sink.
2. The vulnerability class is OS command injection / command execution with attacker-controlled input. Although the finding metadata lists CWE-94, the concrete issue at this sink is shell command injection via PHP `exec()`.
3. Source: user-controlled request body is read from `php://input` on line 84 using `file_get_contents('php://input')`, then parsed by `json_decode(..., TRUE)` and cast to an array.
4. Data flow: `file_get_contents('php://input')` on line 84 → `json_decode(..., TRUE)` on line 84 → `(array)` cast and assignment to `$input` on line 84 → `array_key_exists("target", $input)` existence check on line 85 → `$target = $input['target'];` on line 86 → concatenation into `"ping -c 4 " . $target` and execution by `exec()` on line 88.
5. Validation/sanitization: no command-safe validation or escaping is visible. Line 85 only checks that the `target` key exists; it does not validate hostname/IP syntax, reject shell metacharacters, or apply `escapeshellarg()` / `escapeshellcmd()`.
6. Sink: line 88 executes an OS command through PHP `exec()`. The dangerous operation is shell command construction by concatenating untrusted `$target` into `ping -c 4 ...`.
7. Framework/library protections: none are visible in the provided code. PHP `exec()` does not automatically parameterize or escape shell arguments, and `json_decode()` provides no shell-safety guarantees.
8. Authentication/privilege context is not visible in the provided snippet or prefetched caller context. However, exploitability of the sink itself is clear if this method is reachable with attacker-controlled request input, because the function directly reads `php://input` on line 84.
9. Concrete impact: attacker-controlled `$target` can inject shell metacharacters such as `;`, `&&`, `|`, backticks, or `$()` into line 88, leading to arbitrary OS command execution as the PHP/web-server process.
10. Weakest link: direct concatenation of request-derived `$target` into `exec()` on line 88 without any visible allowlist or shell escaping.
