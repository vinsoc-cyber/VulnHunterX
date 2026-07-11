# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context does not change the analysis because it is unavailable and provides no additional file-consuming use of `$file`. The flagged line is present, but it performs only `fnmatch()` string matching and comparison; no file or network sink is visible on the flagged path.

## Data flow

source `$_GET['page']` (vulnerabilities/fi/source/high.php:4) → assignment to `$file` (line 4) → string validation via `fnmatch("file*", $file)` and comparison `$file != "include.php"` (line 7) → rejected path prints error/exits (lines 8-10); additional context for `global:$file` and `function:<unknown>` was unavailable and showed no further sink

## Answers

1. Step 0 / flagged line location: The flagged line is line 7 in `vulnerabilities/fi/source/high.php`: `if( !fnmatch( "file*", $file ) && $file != "include.php" ) {`. It appears in top-level PHP code / function `<unknown>`. The line contains `fnmatch()` and a string comparison, not a file/network access sink.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP GET input: `$_GET['page']` on line 4.
3. Step 2: The visible data flow is `$_GET['page']` on line 4 → assigned to `$file` on line 4 → used in `fnmatch("file*", $file)` and compared against `"include.php"` on line 7. The additional requested contexts for `global:$file` and `function:<unknown>` were unavailable and do not add any new flow.
4. Step 3: Line 7 performs validation: values are accepted if they match the glob `file*` or are exactly `include.php`; otherwise lines 8-10 print an error and exit. This validation is permissive and could be insufficient if `$file` were later used in a file include/read/fetch sink, but no such sink is visible in the provided code.
5. Step 4: The only visible sink-like operation is `fnmatch("file*", $file)` on line 7. This is a string pattern-matching operation, not a filename dereference, include, file read, or network request. No unsafe file operation is shown.
6. Step 5: No framework protection is visible. PHP’s `fnmatch()` itself does not access the filesystem or network; it only compares strings.
7. Step 6: Based on the visible code, an attacker controlling the query string can set `page` via `$_GET['page']` on line 4. Authentication state is not visible in the provided context.
8. Step 7: In the provided code, the concrete impact is limited to influencing whether execution reaches the error/exit branch on lines 8-10. No SSRF, local file inclusion, file disclosure, RCE, or other file-based impact is demonstrated because `$file` is not used in a file or URL sink.
9. Step 8: The weakest link would be the permissive validation on line 7 if a later file sink existed. However, for this flagged line and visible path, there is no dangerous sink; the user-controlled value reaches only string matching and comparison.
