# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the analysis: the flagged line is present, but it only performs pattern matching and a string comparison on user input. Because no file access, include, URL fetch, or other unsafe filename/SSRF sink is visible at the flagged line or elsewhere in the provided code, this specific finding is not a demonstrated vulnerability.

## Data flow

vulnerabilities/fi/source/high.php:4 `$_GET['page']` → assigned to `$file`; vulnerabilities/fi/source/high.php:7 `$file` → `fnmatch("file*", $file)` and `$file != "include.php"`; vulnerabilities/fi/source/high.php:8-10 invalid input prints `ERROR: File not found!` and exits; no file/network sink is visible, and the additional requested context was unavailable

## Answers

1. Step 0 / flagged line: The flagged line is present at `vulnerabilities/fi/source/high.php:7` and is exactly `if( !fnmatch( "file*", $file ) && $file != "include.php" ) {`. It is in Function: `<unknown>`. The construct present is a validation conditional using PHP `fnmatch()` and a string comparison; it is not a file-open/include/network-fetch sink.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP query input: `$_GET['page']` on line 4.
3. Step 2: Data flow is: `$_GET['page']` is assigned directly to `$file` on line 4, then `$file` is used in `fnmatch("file*", $file)` and compared to `"include.php"` on line 7. If the condition is true, execution prints an error and exits on lines 8-10. The additional requested context was unavailable and does not add any new data-flow steps.
4. Step 3: Validation is applied on line 7. The check permits `$file` only if it matches `file*` or equals `include.php`; otherwise the code exits on lines 8-10. This may or may not be sufficient for a later file operation, but no later file operation is visible. For the flagged line itself, `fnmatch()` is only pattern matching and does not perform file or network access.
5. Step 4: No unsafe sink is visible. The flagged line 7 uses `$file` only as an argument to PHP `fnmatch()` and in a string comparison. There is no visible `include`, `require`, `fopen`, `file_get_contents`, cURL call, stream-wrapper fetch, or other operation that would make this a tainted filename/SSRF sink.
6. Step 5: No framework protections are visible. PHP `fnmatch()` is a standard library pattern-matching function; it does not automatically open files or make server-side requests. No ORM, template engine, routing middleware, or other framework protection is shown.
7. Step 6: Authentication or privilege requirements are not visible. Since the source is `$_GET['page']` on line 4, the input appears HTTP-controllable, potentially by an unauthenticated user, but the surrounding routing/authentication context is not provided.
8. Step 7: From the provided code alone, there is no demonstrated concrete security impact because the tainted value is not used in a dangerous file or network operation. A later unseen sink could change the impact, but none is present in the code under review or in the additional context.
9. Step 8: The weakest visible link is the broad allow condition `fnmatch("file*", $file)` on line 7 if `$file` were later used as a filename. However, for this specific flagged path, the defense chain does not reach a dangerous operation; the flagged operation is validation/pattern matching only.
