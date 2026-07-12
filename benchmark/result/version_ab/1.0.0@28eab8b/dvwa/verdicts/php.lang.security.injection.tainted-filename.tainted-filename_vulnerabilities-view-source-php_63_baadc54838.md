# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source.php:63

**Verdict:** TP · **Confidence:** High (0.87) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line is present in the top-level/unknown function context: line 63, `$source = @file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php" );`, and it contains the reported tainted filename sink. `$security` comes directly from `$_GET` at line 13 and reaches `file_get_contents` at line 63 without visible validation, making this a real tainted filename/local file disclosure issue even though the CWE label of SSRF is not the best match for the visible sink.

## Data flow

vulnerabilities/view_source.php:13 `$_GET['security']` → vulnerabilities/view_source.php:13 `$security` → vulnerabilities/view_source.php:63 interpolated into `DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php"` → vulnerabilities/view_source.php:63 `file_get_contents(...)` reads the constructed path → vulnerabilities/view_source.php:64 `str_replace(...)` modifies the file contents for display → vulnerabilities/view_source.php:89 `highlight_string($source, true)` renders the read contents. Additional requested context for function/global definitions was unavailable and adds no visible sanitizer or guard.

## Answers

1. Step 1: The additional context is unavailable and does not change the prior answer. The visible dangerous source is HTTP GET input: `$security = $_GET[ 'security' ];` at vulnerabilities/view_source.php:13. `$id` is also used in the filename at line 63, but its assignment/source remains not visible.
2. Step 2: The visible data flow remains: vulnerabilities/view_source.php:13 assigns `$_GET['security']` to `$security`; vulnerabilities/view_source.php:63 interpolates `$security` into the path passed to `file_get_contents`. `$id` is used in the `switch` at lines 16-61 and then in the path at line 63, but the additional context did not reveal its source.
3. Step 3: No validation, sanitization, allowlist, canonicalization, or path containment check is visible for `$security` before line 63. The `switch ($id)` on lines 16-61 only sets `$vuln`; even the `default` case on lines 59-60 continues with `$vuln = "Unknown Vulnerability"`. The unavailable global/function context does not add any visible defense.
4. Step 4: The sink is vulnerabilities/view_source.php:63: `$source = @file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php" );`. This is dangerous because a filesystem path is built with user-controlled data and then read. The read contents are later displayed at line 89 with `highlight_string( $source, true )`.
5. Step 5: No automatic framework/library protection is visible. PHP `file_get_contents` does not sanitize path components or prevent traversal. `highlight_string` at line 89 formats output, but it does not protect the file-read sink on line 63.
6. Step 6: Authentication/privilege requirements remain not visible in the provided context. However, the visible source is `$_GET['security']` at line 13, so any user who can reach this script and control query parameters can influence the filename component.
7. Step 7: The concrete visible impact is unauthorized local file/source disclosure via tainted filename/path traversal, because attacker-controlled `$security` can affect which `.php` file is read on line 63 and displayed on line 89. The finding message says SSRF/CWE-918, but the visible exploit class is more directly arbitrary local PHP file read/source disclosure rather than SSRF.
8. Step 8: The weakest link is the direct interpolation of `$security` from `$_GET` into the `file_get_contents` path at line 63 without any visible allowlist such as known security levels, canonical path check, or traversal rejection. The additional context provided no evidence of a complete defense.
