# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** FP · **Confidence:** High (0.86) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The flagged line is present and user input reaches `file_get_contents()`, but the reported vulnerability class is CWE-918 SSRF. On the flagged path, the filename starts with a literal `./` before `$id`, so the attacker-controlled value cannot form the leading URL scheme required for PHP URL-wrapper SSRF at this sink.

## Data flow

vulnerabilities/view_source_all.php:12 `$_GET['id']` → vulnerabilities/view_source_all.php:12 assignment to `$id` → vulnerabilities/view_source_all.php:14 interpolation into fixed relative path `"./{$id}/source/low.php"` → vulnerabilities/view_source_all.php:14 `file_get_contents()`

## Answers

1. Step 0 / flagged line: The flagged line is present at line 14 in `vulnerabilities/view_source_all.php`: `	$lowsrc = @file_get_contents("./{$id}/source/low.php");`. The construct described by the rule is present: user-influenced `$id` is interpolated into a filename argument to `file_get_contents()`. It appears to live in top-level PHP script scope; no named function is visible, and the function is listed as `<unknown>`.
2. Step 1: The dangerous data originates from user-controlled HTTP query input. Line 11 checks `array_key_exists("id", $_GET)`, and line 12 reads `$_GET['id']` into `$id`.
3. Step 2: Data flow is: `$_GET['id']` at line 12 → assigned directly to `$id` at line 12 → interpolated into the string `"./{$id}/source/low.php"` at line 14 → passed to `file_get_contents()` at line 14. The additional requested context for `dvwaPageStartup`, `dvwaPageNewGrab`, and `DVWA_WEB_PAGE_TO_ROOT` was unavailable, so it does not add any new transformation or validation.
4. Step 3: No validation, sanitization, allowlist check, or canonicalization of `$id` is visible between line 12 and the flagged sink on line 14. The later `switch ($id)` starts at line 30, after the file read, so it does not protect line 14. For the specific reported SSRF class, however, the sink argument visibly has a fixed relative-path prefix `./` before attacker-controlled `$id` and a fixed suffix `/source/low.php` on line 14.
5. Step 4: The sink is `@file_get_contents("./{$id}/source/low.php")` at line 14. In general, `file_get_contents()` can be dangerous for SSRF when attacker input controls a URL-form filename such as `http://...`; here, the dangerous operation is file/resource retrieval based on a partly user-controlled filename.
6. Step 5: No framework or library protection is visible for the filename construction. `dvwaPageStartup(array('authenticated'))` at line 6 appears to relate to authentication, but its body is unavailable and no filename validation from it is visible. PHP itself treats URL stream wrappers as schemes when the filename begins with a scheme; the visible argument begins with fixed `./`, not attacker-controlled scheme text.
7. Step 6: The visible code path appears to require an authenticated user because line 6 calls `dvwaPageStartup(array('authenticated'))` before the `$_GET['id']` handling. The exact privilege level is not visible because the implementation of `dvwaPageStartup` is unavailable.
8. Step 7: If the reported CWE-918 condition were exploitable, impact could include SSRF to internal network resources through `file_get_contents()`. In this specific flagged path, the concrete SSRF impact is not demonstrated because the user-controlled value is not at the start of the filename and cannot visibly form a URL scheme due to the fixed `./` prefix on line 14. A separate local path manipulation issue may be possible, but that is not the reported SSRF finding.
9. Step 8: The weakest link is the absence of validation or allowlisting for `$id` before using it in a filesystem path on line 14. For the specific SSRF rule, the visible mitigating property is the fixed relative-path construction `./{$id}/source/low.php`, which prevents `$id` from directly becoming a URL-form filename consumed by `file_get_contents()`.
