# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** TP · **Confidence:** Medium (0.72) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and therefore does not change the analysis: the flagged line visibly passes a path containing unsanitized `$_GET['id']` to `file_get_contents()`. Although the reported SSRF class is not clearly demonstrated because of the `./` prefix, the flagged sink is still genuinely dangerous as a tainted local filename/path traversal file-read with no visible pre-sink defense.

## Data flow

vulnerabilities/view_source_all.php:11 checks for `id` in `$_GET` → vulnerabilities/view_source_all.php:12 assigns user input `$_GET['id']` to `$id` → vulnerabilities/view_source_all.php:14 interpolates `$id` into `"./{$id}/source/low.php"` → vulnerabilities/view_source_all.php:14 passes that path to `file_get_contents()` → vulnerabilities/view_source_all.php:15-16 process the resulting file contents after the read

## Answers

1. Step 0: The flagged line is present at line 14 and is exactly: `$lowsrc = @file_get_contents("./{$id}/source/low.php");`. The construct described by the rule is present on that line: a filename/path passed to PHP `file_get_contents()` is built using `$id`.
2. Q1: The potentially dangerous data originates from user-controlled HTTP query input. Line 11 checks `array_key_exists("id", $_GET)`, and line 12 assigns `$_GET['id']` to `$id`.
3. Q2: Data flow remains unchanged by the additional context because all requested context was unavailable. The visible flow is: `$_GET['id']` at line 12 → `$id` at line 12 → string interpolation in `"./{$id}/source/low.php"` at line 14 → `file_get_contents()` at line 14. Related but non-flagged sibling reads occur on lines 18, 22, and 26.
4. Q3: No validation, sanitization, allowlist, canonicalization, or encoding of `$id` is visible before the flagged sink on line 14. The `switch ($id)` beginning on line 30 is after the file reads, so it cannot protect line 14. The post-read `str_replace()` and `highlight_string()` calls on lines 15-16 process file contents, not the filename.
5. Q4: The sink is `file_get_contents()` on line 14. The dangerous operation is a server-side file read where the pathname includes attacker-controlled input. The exact CWE label says SSRF, but because the path is prefixed with `./`, the clearly visible risk at this sink is more accurately tainted local filename/path traversal rather than a direct URL-based SSRF.
6. Q5: The new context does not show any framework or library protection. `dvwaPageStartup(array('authenticated'))` on line 6 is visible but its body was unavailable, and in any case no visible pre-sink path validation is shown. PHP `file_get_contents()` itself does not automatically restrict attacker-controlled path traversal, and the `@` operator on line 14 only suppresses errors.
7. Q6: Based on line 6, the code path appears to require an authenticated user because `dvwaPageStartup(array('authenticated'))` is called. No admin-only requirement is visible in the provided code.
8. Q7: If an attacker controls `$id`, the concrete impact is unauthorized server-side file/path selection for a read operation. Because the resulting file contents are assigned to `$lowsrc` and then highlighted on line 16, the likely impact is disclosure of readable source files matching the constructed path pattern. Direct SSRF is not clearly established due to the `./` prefix.
9. Q8: The weakest link is the direct use of `$_GET['id']` in the file path at line 14 before any visible allowlist or canonicalization. The later `switch ($id)` on line 30 is too late to defend the flagged sink, and the additional requested context was unavailable, so it does not add any defense.
