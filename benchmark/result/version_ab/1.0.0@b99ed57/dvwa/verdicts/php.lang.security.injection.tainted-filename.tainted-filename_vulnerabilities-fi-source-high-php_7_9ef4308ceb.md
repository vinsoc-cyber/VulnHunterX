# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not change the analysis: the flagged line is visible and is only a validation conditional using `fnmatch()` and string comparison. Because the flagged line does not dereference a filename or URL and no downstream file/network sink is shown, this specific finding is a false positive.

## Data flow

`vulnerabilities/fi/source/high.php:4` user-controlled `$_GET['page']` → `vulnerabilities/fi/source/high.php:4` assignment to `$file` → `vulnerabilities/fi/source/high.php:7` validation with `fnmatch("file*", $file)` and `$file != "include.php"` → `vulnerabilities/fi/source/high.php:8-10` error and `exit` on failed validation; no visible file/network sink

## Answers

1. Step 0 / Locate flagged line: The flagged line is present at `vulnerabilities/fi/source/high.php:7` and its exact text is `if( !fnmatch( "file*", $file ) && $file != "include.php" ) {`. It lives in Function: `<unknown>`, apparently top-level PHP script code in the provided snippet. The construct present on this line is a conditional validation check using `fnmatch()` and a string comparison, not a file read/include or network request sink.
2. Step 1 / Source: The potentially dangerous data originates from user-controlled HTTP query input: `$_GET['page']` on line 4, assigned directly to `$file`.
3. Step 2 / Trace: `$_GET['page']` at line 4 → assigned to `$file` at line 4 → `$file` used in `fnmatch("file*", $file)` and compared to `"include.php"` at line 7 → if validation fails, execution prints an error and exits at lines 8-10. The additional requested context was unavailable and does not add any new visible flow.
4. Step 3 / Validation/Sanitization: Line 7 performs validation: it allows values matching `file*` or exactly equal to `include.php`; otherwise lines 8-10 reject and exit. This is not a complete sanitizer for a hypothetical later file/URL sink, but no such sink is visible in the provided code. The flagged line itself is only validation.
5. Step 4 / Sink: The flagged operation is line 7, `fnmatch()` inside an `if` condition. This is not an unsafe filename or SSRF sink because it does not open, include, fetch, or otherwise dereference a file path or URL. No operation such as `include`, `require`, `file_get_contents`, `fopen`, `readfile`, `curl_exec`, or similar is visible.
6. Step 5 / Framework/Library protections: No framework is visible. PHP’s `fnmatch()` only performs string pattern matching; it provides no automatic SSRF/path traversal protection, but it also does not itself perform a dangerous file or network operation.
7. Step 6 / Privilege level: Not visible in provided context. The use of `$_GET` on line 4 indicates HTTP-controlled input, but authentication, authorization, and routing state are not shown.
8. Step 7 / Security impact: Based only on the provided code, no concrete security impact is demonstrated. The code reads user input, checks it, and exits on failure; there is no visible file inclusion, local file read, remote URL fetch, SSRF, RCE, data theft, privilege escalation, or DoS sink.
9. Step 8 / Weakest link: The weakest visible defense is the broad allow pattern `file*` on line 7, which could be unsafe if `$file` were later used in a file/URL sink. However, for this finding’s flagged line, no such sink is present; the visible operation is benign pattern matching and comparison.
