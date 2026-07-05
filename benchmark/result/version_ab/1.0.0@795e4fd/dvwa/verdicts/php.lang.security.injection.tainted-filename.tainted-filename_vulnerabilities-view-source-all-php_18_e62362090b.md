# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** FP · **Confidence:** High (0.88) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The new context is unavailable and does not change the trace: user input reaches `file_get_contents()` on line 18 without validation. But the reported vulnerability class is SSRF, and the exact flagged path begins with the fixed literal `./`, so the attacker cannot make the filename start with a remote URL scheme; this may be a path traversal concern, but not the SSRF issue reported by this rule.

## Data flow

vulnerabilities/view_source_all.php:11 checks for `id` in `$_GET` → vulnerabilities/view_source_all.php:12 assigns `$_GET['id']` to `$id` → vulnerabilities/view_source_all.php:18 interpolates `$id` into `"./{$id}/source/medium.php"` → vulnerabilities/view_source_all.php:18 passes the resulting relative path to `file_get_contents()`

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 18 and its exact text is `$medsrc = @file_get_contents("./{$id}/source/medium.php");`. The construct described by the rule is present on that line: a filename/path argument to `file_get_contents()` is built using `$id`, which comes from request input. The code appears to live at top-level script scope in `vulnerabilities/view_source_all.php`; no named enclosing function is visible.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP query input. Line 11 checks `array_key_exists("id", $_GET)`, and line 12 assigns `$_GET['id']` directly to `$id`.
3. Step 2: Data flow is: `$_GET['id']` is read at line 12 → assigned directly to `$id` at line 12 → interpolated into the string `"./{$id}/source/medium.php"` at line 18 → passed to `file_get_contents()` at line 18. Similar sibling flows are visible at lines 14, 22, and 26, but the flagged sink is specifically line 18.
4. Step 3: No validation, sanitization, whitelist, canonicalization, or encoding is visible before the sink on line 18. The later `switch ($id)` beginning at line 30 does not protect the flagged sink because it occurs after the `file_get_contents()` calls on lines 14, 18, 22, and 26.
5. Step 4: The sink is `file_get_contents()` at line 18. The dangerous operation is using user-controlled data to construct a filename/path. For the specific reported CWE-918 SSRF class, however, the argument starts with a literal `./`, making the resulting string a relative local filesystem path rather than an attacker-controlled URL beginning with a scheme such as `http://`, `https://`, or `php://`.
6. Step 5: The additional requested context for `dvwaPageStartup`, `allow_url_fopen`, and PHP stream-wrapper configuration was unavailable, so no framework-level automatic protection can be confirmed from that context. The visible, specific defense against SSRF is the literal local-path prefix `./` on line 18; PHP stream wrappers are invoked by URL-style scheme prefixes at the start of the filename, and the attacker-controlled `$id` does not control the beginning of the string.
7. Step 6: The visible code calls `dvwaPageStartup(array('authenticated'))` on line 6, suggesting the page is intended to require an authenticated user. The implementation of `dvwaPageStartup` is unavailable, so exact authentication enforcement is not visible in the provided context.
8. Step 7: If an attacker controls `$id`, the concrete visible impact is local path manipulation/path traversal into a path constrained by the fixed prefix `./` and suffix `/source/medium.php`. For the specific SSRF finding, a concrete server-side request impact is not demonstrated because the constructed filename cannot begin with an attacker-supplied remote URL scheme.
9. Step 8: The weakest link is the lack of validation or whitelisting of `$id` before filesystem use on line 18. However, for this rule’s specific SSRF claim, the defense is complete in the visible path because the sink argument is forced to begin with `./`, preventing `$id` from supplying the URL scheme needed for SSRF via `file_get_contents()`.
