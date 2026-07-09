# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is a real tainted filename sink: authenticated user input from `$_GET['id']` flows directly into `file_get_contents()` with no visible validation before the read. The issue is more accurately local file/path traversal-style disclosure than SSRF because the constructed path begins with `./`, but the flagged sink remains exploitable based on the visible data flow.

## Data flow

HTTP GET parameter `$_GET['id']` in vulnerabilities/view_source_all.php line 12, after existence check on line 11 → assigned directly to `$id` on line 12 → interpolated into `"./{$id}/source/medium.php"` on line 18 → used as the filename argument to `file_get_contents()` on line 18 → contents assigned to `$medsrc` on line 18 → post-read formatting via `str_replace()` on line 19 and `highlight_string()` on line 20. Additional requested context for `dvwaPageStartup` / global `$_GET` was unavailable and does not add any visible sanitizer.

## Answers

1. Step 0 / flagged line: The exact flagged line is line 18: `$medsrc = @file_get_contents("./{$id}/source/medium.php");`. The flagged construct is present: `$id` is interpolated into a filename passed to PHP `file_get_contents()`. Function/scope: the provided context says `Function: <unknown>`; the code appears to be top-level script code in `vulnerabilities/view_source_all.php`, not a named function.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP GET input. Line 11 checks for the presence of `id` in `$_GET`, and line 12 assigns `$_GET['id']` directly to `$id`.
3. Step 2: Data flow: `$_GET['id']` is checked for existence at line 11, assigned directly to `$id` at line 12, interpolated into the path string `"./{$id}/source/medium.php"` at line 18, and passed to `file_get_contents()` at line 18. The returned contents are then assigned to `$medsrc` at line 18, modified with `str_replace()` at line 19, and passed to `highlight_string()` at line 20.
4. Step 3: No validation, sanitization, canonicalization, allowlist check, or encoding of `$id` is visible before the file read on line 18. The `switch ($id)` begins at line 30, after the file reads on lines 14, 18, 22, and 26, so it does not protect the flagged sink. The additional requested context for `dvwaPageStartup` and global `$_GET` was unavailable, so no upstream sanitizer is visible in the provided context.
5. Step 4: The sink is `file_get_contents()` at line 18. The unsafe operation is server-side file access using a path partly controlled by the `id` request parameter. Although the rule description mentions SSRF, the visible path is prefixed with `./`, so the directly supported class is tainted filename / path traversal-style local file read rather than clearly remote SSRF.
6. Step 5: No framework or library automatic protection is visible at the sink. `dvwaPageStartup(array('authenticated'))` is called at line 6, but its implementation was not provided and there is no visible evidence that it sanitizes `$_GET['id']` or constrains filesystem paths. PHP `file_get_contents()` itself does not safely validate user-controlled path segments.
7. Step 6: An attacker appears to need an authenticated session because line 6 calls `dvwaPageStartup(array('authenticated'))`. No admin-only or higher privilege check is visible in the provided code.
8. Step 7: If an authenticated attacker controls `id`, they can influence which server-side path is read by `file_get_contents()` on line 18. The concrete impact visible here is unauthorized local file/source disclosure for files reachable through paths matching `./<attacker-controlled>/source/medium.php`; the fixed prefix and suffix constrain the read but do not eliminate traversal risk.
9. Step 8: The weakest link is the direct use of `$_GET['id']` from line 12 in a filesystem path at line 18 without any visible allowlist or canonical path validation before the file read. A later `switch ($id)` at line 30 may identify known vulnerability names for display, but it is too late to defend the file access.
