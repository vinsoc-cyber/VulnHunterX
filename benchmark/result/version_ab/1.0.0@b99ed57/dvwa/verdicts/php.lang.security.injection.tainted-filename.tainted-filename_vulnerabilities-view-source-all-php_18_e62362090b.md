# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** MISS · **Iterations:** 5

## Reasoning

Although unsanitized `$_GET['id']` reaches `file_get_contents()` on line 18, the flagged SSRF condition is prevented by the visible path construction: the argument always begins with `./`, so user input cannot supply a PHP URL-wrapper scheme at the start of the filename. No clearly exploitable local file disclosure is proven from the provided slice because the path also has a fixed suffix and the final output context is unavailable.

## Data flow

HTTP query parameter `$_GET['id']` (line 12) → assignment to `$id` (line 12) → interpolation into relative path `"./{$id}/source/medium.php"` (line 18) → `file_get_contents()` filename sink (line 18) → `$medsrc` (line 18) → `str_replace()` (line 19) → `highlight_string(..., true)` (line 20)

## Answers

1. Step 0 / flagged line: The flagged line is line 18: `$medsrc = @file_get_contents("./{$id}/source/medium.php");`. The reported construct is present: `file_get_contents()` is called with a filename/path that includes `$id`.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP query input. Line 11 checks whether `id` exists in `$_GET`, and line 12 assigns `$_GET['id']` directly to `$id`.
3. Step 2: The data flow is unchanged because the additional context was unavailable. Flow: `$_GET['id']` on line 12 → direct assignment to `$id` on line 12 → interpolation into the filename string `"./{$id}/source/medium.php"` on line 18 → filename argument to `file_get_contents()` on line 18 → result assigned to `$medsrc` on line 18 → transformed by `str_replace()` on line 19 → transformed by `highlight_string($medsrc, true)` on line 20.
4. Step 3: No validation, sanitization, whitelist check, or canonicalization of `$id` is visible before line 18. The `switch ($id)` beginning at line 30 occurs after the file reads, so it cannot sanitize the value before the sink. However, for the specific SSRF concern, the filename is visibly prefixed with the literal `./` and suffixed with `/source/medium.php` on line 18, so attacker input cannot make the filename begin with a URL scheme such as `http://`, `https://`, or another PHP stream-wrapper scheme.
5. Step 4: The sink is `file_get_contents()` on line 18. The operation would be dangerous for SSRF if attacker input controlled a URL passed to `file_get_contents()`. Here, the constructed argument is a relative filesystem path of the form `./<id>/source/medium.php`, not a directly attacker-controlled URL.
6. Step 5: No framework or library automatic protection is visible. Line 6 calls `dvwaPageStartup(array('authenticated'))`, which indicates an authentication check, but no framework-level filename sanitization is shown. The SSRF-specific protection comes from the visible string construction on line 18: the user-controlled data is not at the beginning of the filename where a PHP URL wrapper scheme would be recognized.
7. Step 6: Based on visible code, an attacker must be authenticated because `dvwaPageStartup(array('authenticated'))` is called on line 6. No admin-only requirement is visible.
8. Step 7: The SSRF impact claimed by the finding is not achievable from the visible sink because the `file_get_contents()` argument begins with `./`, preventing direct remote URL control. A separate local path manipulation concern might exist because `$id` is not whitelisted, but arbitrary file disclosure is not clearly established from the provided code due to the fixed prefix/suffix and missing final rendering context.
9. Step 8: For SSRF, the defense is complete in the visible code because the filename cannot start with an attacker-controlled URL scheme; it is forced to start with `./`. The weakest unrelated issue is lack of `$id` whitelisting for local filesystem path construction, but that does not make this flagged SSRF finding clearly exploitable.
