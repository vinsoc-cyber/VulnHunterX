# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context is unavailable and does not change the analysis: the exact flagged line is visible and contains only `fnmatch()` plus a string comparison. Because the reported sink line does not perform file or network I/O, and no downstream sink is visible in this finding, this specific Semgrep finding is a false positive.

## Data flow

source `$_GET['page']` at vulnerabilities/fi/source/high.php:4 → assignment to `$file` at line 4 → string-pattern validation `fnmatch("file*", $file)` and comparison `$file != "include.php"` at flagged line 7 → no visible file/network sink; requested additional context for `function:<unknown>`, `global:$file`, and `global:$_GET` was unavailable

## Answers

1. Step 0 / flagged line location: The flagged line is present at `vulnerabilities/fi/source/high.php:7` and its exact text is `if( !fnmatch( "file*", $file ) && $file != "include.php" ) {`. This line contains a `fnmatch()` string-pattern validation and a string comparison; it does not contain a file read/include/write or network request operation.
2. Step 1 / source: The potentially dangerous data originates from user-controlled HTTP GET input: `$_GET['page']` at `vulnerabilities/fi/source/high.php:4`.
3. Step 2 / trace: `$_GET['page']` is assigned directly to `$file` at line 4. `$file` then flows into `fnmatch("file*", $file)` and into the comparison `$file != "include.php"` at line 7. No additional caller/function/global context was available, so no further use is visible.
4. Step 3 / validation/sanitization: The visible validation is line 7: values are rejected only if they do not match `file*` and are not exactly `include.php`. This would be insufficient as a complete filename or URL sanitizer if `$file` were later passed to a file/URL sink, but no such sink is visible in the provided context.
5. Step 4 / sink: The flagged operation is `fnmatch()` at line 7. In PHP, `fnmatch()` performs shell-style string pattern matching; it does not open a file, include a file, fetch a URL, or perform SSRF-capable I/O. Therefore, the flagged line itself is not an unsafe filename sink.
6. Step 5 / framework/library protections: No framework protections are visible. The relevant library behavior is PHP standard `fnmatch()`, which is a string comparison/pattern-matching function and is not itself dangerous for SSRF or file access.
7. Step 6 / privilege/authentication: The source is an HTTP GET parameter on line 4. No authentication or authorization checks are visible in the provided snippet, so the input appears externally controllable from the shown code.
8. Step 7 / concrete impact: For the visible flagged path, no concrete security impact is demonstrated because the data only reaches a string-pattern check. A later hidden `include`, `require`, `fopen`, `file_get_contents`, or URL-fetch operation could create LFI/path traversal/SSRF risk, but such an operation is not present in the provided code.
9. Step 8 / weakest link: The weakest visible defense is the incomplete allowlist on line 7. However, for this specific finding, the defense chain does not reach a dangerous sink in the shown code; the flagged line is present-but-harmless because it only validates/compares strings.
