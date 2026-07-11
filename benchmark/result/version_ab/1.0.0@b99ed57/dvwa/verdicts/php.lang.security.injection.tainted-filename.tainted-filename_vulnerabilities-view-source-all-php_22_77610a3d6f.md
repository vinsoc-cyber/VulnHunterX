# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** TP · **Confidence:** High (0.84) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present in top-level PHP script scope, not a named function, and it directly reads a filename containing `$id` from `$_GET` with no visible validation before the sink. The precise exploitable class is tainted filename / constrained local file read rather than SSRF, but the flagged sink is still genuinely dangerous on the shown path.

## Data flow

vulnerabilities/view_source_all.php:12 `$_GET['id']` → vulnerabilities/view_source_all.php:12 `$id` → vulnerabilities/view_source_all.php:22 interpolated into `"./{$id}/source/high.php"` → vulnerabilities/view_source_all.php:22 `file_get_contents(...)` reads the path → vulnerabilities/view_source_all.php:23 `str_replace(...)` → vulnerabilities/view_source_all.php:24 `highlight_string(...)`; requested additional context for `dvwaPageStartup`, `allow_url_fopen`, and `open_basedir` was unavailable and adds no visible defense

## Answers

1. Step 1 / source: The potentially dangerous data originates from user-controlled HTTP query input. Line 11 checks `array_key_exists("id", $_GET)`, and line 12 assigns `$id = $_GET['id'];`. The additional context for `dvwaPageStartup` and PHP globals was unavailable, so it does not change this answer.
2. Step 2 / trace: The visible flow is `$_GET['id']` at line 12 → `$id` at line 12 → direct interpolation into filesystem paths at lines 14, 18, 22, and 26. The flagged path is line 22 exactly: `$highsrc = @file_get_contents("./{$id}/source/high.php");`. After the sink, the result flows to `str_replace` on line 23 and `highlight_string` on line 24.
3. Step 3 / validation, sanitization, encoding: No validation or sanitization is visible before the flagged sink on line 22. Line 11 only checks whether the `id` parameter exists. The `switch ($id)` beginning on line 30 resembles an allowlist of known IDs, but it occurs after the file reads on lines 14, 18, 22, and 26, so it does not protect the flagged sink. The unavailable additional context provides no visible sanitizer or guard.
4. Step 4 / sink: The sink is the flagged line 22: `$highsrc = @file_get_contents("./{$id}/source/high.php");`. The dangerous operation is `file_get_contents` reading a server-side file path built from user-controlled input. Because the string begins with `./`, the visible issue is better characterized as tainted filename / constrained path traversal or local file read, not classic SSRF.
5. Step 5 / framework or library protections: No automatic protection is visible. PHP `file_get_contents` does not automatically whitelist path components or prevent directory traversal. The `@` operator on line 22 only suppresses errors and provides no security protection. Requested context for `dvwaPageStartup`, `allow_url_fopen`, and `open_basedir` was unavailable, so no framework or configuration-level defense is visible.
6. Step 6 / required privilege: Line 6 calls `dvwaPageStartup(array('authenticated'));`, so the visible code indicates the attacker must be authenticated. The exact behavior of `dvwaPageStartup` is not visible because the requested context was unavailable. No admin-only requirement is visible.
7. Step 7 / concrete impact: An authenticated attacker controlling `id` can influence which server-side path is read by `file_get_contents` on line 22, subject to the fixed prefix `./` and suffix `/source/high.php`. The file contents are then transformed for source display by `str_replace` and `highlight_string` on lines 23-24. The concrete impact is unauthorized local source/file disclosure for reachable files matching the constructed path pattern, rather than SSRF.
8. Step 8 / weakest link: The weakest link is that untrusted `$_GET['id']` is used in the file path before any visible allowlist or canonicalization. The apparent allowlist-like `switch ($id)` starts only at line 30, after the dangerous reads have already occurred.
