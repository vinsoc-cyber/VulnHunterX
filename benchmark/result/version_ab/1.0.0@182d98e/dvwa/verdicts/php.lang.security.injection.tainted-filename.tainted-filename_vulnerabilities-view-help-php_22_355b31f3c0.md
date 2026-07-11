# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_help.php:22

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The newly supplied context is unavailable and does not change the visible analysis: authenticated user-controlled `$_GET` values flow directly into the flagged filename sink at line 22 without any visible sanitization or allowlisting. The risk is stronger than SSRF alone because the selected file contents are immediately evaluated with `eval()` on the same line.

## Data flow

vulnerabilities/view_help.php:11-13 checks only that $_GET keys exist → vulnerabilities/view_help.php:14 assigns $_GET['id'] to $id → vulnerabilities/view_help.php:16 assigns $_GET['locale'] to $locale → vulnerabilities/view_help.php:19 branches on $locale == 'en' → vulnerabilities/view_help.php:22 interpolates $id and $locale into `DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php"` → vulnerabilities/view_help.php:22 passes that path to file_get_contents() → vulnerabilities/view_help.php:22 passes returned contents to eval()

## Answers

1. Step 0 / flagged line location: The flagged line is `vulnerabilities/view_help.php:22`: `eval( '?>' . file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php" ) . '<?php ' );`. The rule-described construct is present on that exact line: a filename/path built using variables derived from request input is passed to `file_get_contents()`. The line also evaluates the fetched contents with `eval()`. The code is in top-level PHP script scope; the provided context labels the function as `<unknown>`, not a named function.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP query parameters in `$_GET`. The code checks for the presence of `id`, `security`, and `locale` in `$_GET` on lines 11-13, then assigns `$_GET['id']` to `$id` on line 14 and `$_GET['locale']` to `$locale` on line 16.
3. Step 2: Data flow: `$_GET['id']` on line 14 → `$id` on line 14 → interpolated into `"vulnerabilities/{$id}/help/help.{$locale}.php"` on line 22. Separately, `$_GET['locale']` on line 16 → `$locale` on line 16 → compared to `'en'` on line 19 → if not equal to `'en'`, interpolated into the filename on line 22. The constructed filename is passed to `file_get_contents()` on line 22, and the returned contents are concatenated into a string passed to `eval()` on the same line.
4. Step 3: No validation, sanitization, encoding, allowlist, canonicalization, basename enforcement, locale whitelist, or path traversal check is visible for `$id` or `$locale`. Lines 11-13 only check key existence. The comparison `$locale == 'en'` on line 19 only selects the branch; it does not sanitize `$locale` for the flagged line 22. The requested additional function/global contexts were unavailable, so they provide no visible defense that changes this assessment.
5. Step 4: The sink is line 22: `file_get_contents()` is called with a path containing `$id` and `$locale`, and its result is immediately passed to `eval()`. The unsafe operation is both attacker-influenced file selection and evaluation of the selected file contents as PHP code.
6. Step 5: No framework or library automatic protection is visible at this sink. `dvwaPageStartup(array('authenticated'))` on line 6 may enforce authentication, but its body was unavailable and no visible sanitization of `$_GET` is shown. `file_get_contents()` and `eval()` do not provide automatic protection against attacker-controlled filenames or code evaluation.
7. Step 6: The visible code calls `dvwaPageStartup(array('authenticated'))` on line 6, so the apparent required privilege level is an authenticated user. No admin-only check is visible.
8. Step 7: The concrete impact is attacker-influenced local file inclusion / arbitrary server-side file read through `file_get_contents()` on line 22, with potential code execution because the fetched contents are passed into `eval()` on the same line. Exploitability of full RCE depends on whether an attacker can place or target PHP content at a matching path, but the flagged sink itself is unsafe.
9. Step 8: The weakest link is the direct interpolation of unsanitized `$_GET`-derived `$id` and `$locale` into a filesystem path on line 22, followed immediately by `eval()`. The additional context was unavailable and therefore does not establish any complete defense.
