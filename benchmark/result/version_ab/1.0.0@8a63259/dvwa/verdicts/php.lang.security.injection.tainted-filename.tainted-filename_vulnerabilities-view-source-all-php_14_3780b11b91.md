# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** FP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The tainted filename pattern is present, but the reported vulnerability class is CWE-918 SSRF. On the flagged path, the sink argument always starts with the literal `./`, so the attacker-controlled `$id` cannot supply the leading URL scheme required for `file_get_contents()` to make a server-side request; any remaining concern would be a separate local file/path traversal issue, not the reported SSRF finding.

## Data flow

`$_GET['id']` source (`vulnerabilities/view_source_all.php:11-12`) → direct assignment to `$id` (`vulnerabilities/view_source_all.php:12`) → interpolation into `"./{$id}/source/low.php"` (`vulnerabilities/view_source_all.php:14`) → `file_get_contents()` filename sink (`vulnerabilities/view_source_all.php:14`). Additional requested context for `allow_url_fopen`, stream wrappers, and `dvwaPageStartup` was unavailable and did not alter this trace.

## Answers

1. Step 0 / flagged line: The flagged line is line 14: `$lowsrc = @file_get_contents("./{$id}/source/low.php");`. The construct described by the rule is present on that line: `file_get_contents()` is called with a filename/path string containing user-controlled `$id`. The function is shown as `<unknown>`; in the provided snippet it appears to be top-level PHP script code rather than a named function.
2. Step 1: The dangerous data originates from user-controlled HTTP query input: `$_GET['id']`. The code checks only whether the key exists on line 11 and then reads it on line 12.
3. Step 2: The data flow is: `$_GET['id']` existence check at line 11 → direct assignment `$id = $_GET['id'];` at line 12 → interpolation into the filename string `"./{$id}/source/low.php"` at line 14 → passed to `file_get_contents()` at line 14. The same `$id` is also interpolated into additional `file_get_contents()` calls on lines 18, 22, and 26.
4. Step 3: No validation, sanitization, allowlist, canonicalization, or encoding is applied to `$id` before the flagged sink on line 14. The `switch ($id)` starting on line 30 is after the file reads, so it cannot protect line 14. The additional requested context for `allow_url_fopen`, PHP stream wrappers, and `dvwaPageStartup` was unavailable, so it does not add any visible sanitization or protection.
5. Step 4: The sink is `file_get_contents()` on line 14. The unsafe operation is using user-influenced data as part of a file path. For the specific reported CWE-918 SSRF class, the important detail is that the actual sink argument visibly begins with the fixed literal prefix `./`, before the user-controlled `$id`.
6. Step 5: No framework or library protection for the filename is visible. `dvwaPageStartup(array('authenticated'))` on line 6 may enforce authentication, but its body was unavailable and it is not visible as a filename sanitizer. No ORM, templating auto-escaping, or parameterization mechanism is relevant to this file-read sink.
7. Step 6: The visible code calls `dvwaPageStartup(array('authenticated'))` on line 6, so triggering the path appears to require an authenticated user. The implementation is not visible, so the exact authentication enforcement is not confirmed from provided code.
8. Step 7: If an attacker controls `$id`, the visible risk is unintended local filesystem path access/path traversal-style behavior because `$id` is embedded into a local path on lines 14, 18, 22, and 26. However, the reported issue is SSRF, and SSRF is not clearly reachable from line 14 because PHP URL wrappers require a URL scheme at the beginning of the filename, while this argument is forced to begin with `./`.
9. Step 8: The weakest link is the lack of validation or allowlisting for `$id` before it is used in file paths. But for this specific SSRF finding, the visible fixed `./` prefix at the beginning of `file_get_contents("./{$id}/source/low.php")` on line 14 prevents attacker input from becoming a leading remote URL scheme such as `http://`.
