# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present, but the reported SSRF/tainted-filename sink is absent there: `fnmatch()` only performs string pattern matching and does not access files or network resources. Although the validation would be weak before a later file/URL sink, no such sink is visible in the provided code or additional context.

## Data flow

user input `$_GET['page']` (line 4) → assignment to `$file` (line 4) → string pattern check `fnmatch("file*", $file)` and comparison `$file != "include.php"` (line 7) → no visible file/URL/network sink

## Answers

1. Step 0 / flagged line located: line 7 is `if( !fnmatch( "file*", $file ) && $file != "include.php" ) {`. The line contains a PHP `fnmatch()` pattern-matching check and a string comparison; it does not contain a file/URL access operation such as `include`, `require`, `fopen`, `file_get_contents`, cURL, or another SSRF-capable sink.
2. Step 1: The potentially dangerous data originates from user input: `$_GET['page']` on line 4, an HTTP GET query parameter.
3. Step 2: The data flow is: `$_GET['page']` on line 4 → assigned directly to `$file` on line 4 → `$file` is passed to `fnmatch("file*", $file)` and compared to `"include.php"` on line 7. The newly provided context is unavailable and adds no further flow.
4. Step 3: Validation is applied on line 7: the code allows values matching `file*` or exactly equal to `include.php`. This is broad and would not be a complete filename/URL sanitizer if `$file` were later used in a file/network sink. However, at the flagged line, the operation is only pattern matching/comparison, not file or network access.
5. Step 4: No unsafe SSRF/file sink is visible. The only sink-like operation shown is `fnmatch()` on line 7, but PHP `fnmatch()` performs string pattern matching and does not fetch URLs, open files, include files, or make network requests.
6. Step 5: No framework protection is visible. The relevant language/library behavior is PHP standard library behavior: `fnmatch()` is not a file access API; it only matches a string against a shell wildcard pattern.
7. Step 6: Authentication or privilege requirements are not visible in the provided context. The input is from a GET parameter on line 4, but access control for this PHP file is not shown.
8. Step 7: If `$file` were later used in a file include/read or URL-fetch operation, possible impacts could include SSRF, file disclosure, or file inclusion. But no such operation is present at or after the flagged line in the provided code, so the reported SSRF impact is not demonstrated.
9. Step 8: For the reported rule, the weakest link is not an exploitable sink but the rule match itself: the flagged line uses tainted data in `fnmatch()`, which is not an SSRF-capable operation. The visible code does not show the dangerous operation required for this vulnerability class.
