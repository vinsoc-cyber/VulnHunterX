# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** TP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not change the visible data flow: user-controlled `$_GET['id']` reaches `file_get_contents()` in a filename on line 22 with no visible validation before the sink. The rule's SSRF wording is not the best fit because the path is prefixed with `./`, but the flagged sink is still genuinely dangerous as a tainted server-side filename/local file read risk.

## Data flow

HTTP query parameter `$_GET['id']` (`vulnerabilities/view_source_all.php:11-12`) → assigned to `$id` (`line 12`) → interpolated into `"./{$id}/source/high.php"` (`line 22`) → passed to `file_get_contents()` sink (`line 22`) → assigned to `$highsrc` (`line 22`) → transformed by `str_replace()` (`line 23`) → transformed by `highlight_string()` (`line 24`)

## Answers

1. Step 0 / flagged line: The flagged line is present at `vulnerabilities/view_source_all.php:22` and is exactly `$highsrc = @file_get_contents("./{$id}/source/high.php");`. The suspicious construct is present: user-controlled `$id` is interpolated into a filename passed to `file_get_contents()`.
2. Function location: The provided code is labeled `Function: <unknown>` and appears to be top-level PHP script code in `vulnerabilities/view_source_all.php`, not inside a visible named function. The additional requested context for `dvwaPageStartup`, `dvwaPageNewGrab`, `$_GET`, and the whole file was unavailable, so this does not change.
3. Step 1: The potentially dangerous data originates from HTTP query-string user input: `$_GET['id']` is checked with `array_key_exists("id", $_GET)` on line 11 and assigned to `$id` on line 12.
4. Step 2: Data flow remains unchanged by the additional context: `$_GET['id']` at lines 11-12 → `$id` assignment at line 12 → string interpolation into `"./{$id}/source/high.php"` at line 22 → `file_get_contents()` on line 22 → `$highsrc` assigned on line 22 → `$highsrc` passed through `str_replace()` on line 23 → `$highsrc` passed to `highlight_string()` on line 24.
5. Step 3: No validation, sanitization, allowlist, canonicalization, or path normalization is visible before the sink on line 22. The `switch ($id)` beginning at line 30 is after the file reads on lines 14, 18, 22, and 26, so it does not protect the flagged `file_get_contents()` call. The additional context did not provide any upstream sanitizer.
6. Step 4: The sink is `file_get_contents()` at line 22. The unsafe operation is server-side file access using a path partially controlled by the HTTP request parameter `$id`. Although the rule message references SSRF, the visible issue is more directly a tainted filename/path traversal/local file read risk at this sink.
7. Step 5: No framework or library protection is visible. `file_get_contents()` does not automatically restrict traversal or enforce an allowlist, and the `@` operator on line 22 only suppresses errors. The body of `dvwaPageStartup()` from line 6 was not available, so no automatic protection can be confirmed there.
8. Step 6: Line 6 calls `dvwaPageStartup(array('authenticated'))`, so the visible code suggests the attacker must be authenticated. The exact implementation of that authentication check is not visible in the provided or additional context.
9. Step 7: If an authenticated attacker controls `$id`, they can influence which server-side path is read by `file_get_contents()` on line 22. The likely impact is unintended local file/source disclosure for files matching the constructed path pattern, especially because the result is syntax-highlighted on line 24 and likely intended for display, though the final rendering is not visible in the slice.
10. Step 8: The weakest link is the missing allowlist/path validation before line 22. The code appears to know the intended valid IDs in the `switch` at lines 30-72, but that check occurs only after the dangerous file reads, so it is ineffective for the flagged sink.
