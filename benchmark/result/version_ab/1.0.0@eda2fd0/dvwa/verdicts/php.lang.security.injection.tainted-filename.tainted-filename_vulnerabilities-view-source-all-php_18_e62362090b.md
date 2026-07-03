# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** FP · **Confidence:** Medium (0.8) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The tainted filename flow is real, but the reported vulnerability class is SSRF/CWE-918. On the flagged path, the filename is visibly forced to begin with `./`, so attacker input cannot make the `file_get_contents` argument begin with a URL wrapper scheme such as `http://`; any remaining concern would be local path manipulation, not the reported SSRF.

## Data flow

`vulnerabilities/view_source_all.php:11` checks whether `$_GET` contains `id` → `vulnerabilities/view_source_all.php:12` assigns user input `$_GET['id']` to `$id` → `vulnerabilities/view_source_all.php:18` interpolates `$id` into the fixed relative path string `"./{$id}/source/medium.php"` → `vulnerabilities/view_source_all.php:18` passes that string to PHP built-in `file_get_contents`

## Answers

1. Step 1: The potentially dangerous data originates from user-controlled HTTP query input: `$_GET['id']` is checked at `vulnerabilities/view_source_all.php:11` and read at line 12. The additional context for `global:$_GET` was unavailable, so no upstream normalization or validation is visible.
2. Step 2: Data flow remains unchanged with the additional context: `$_GET['id']` at line 12 → assigned directly to `$id` at line 12 → interpolated into file paths at lines 14, 18, 22, and 26 → passed to `file_get_contents`. The exact flagged line is `	$medsrc = @file_get_contents("./{$id}/source/medium.php");` at `vulnerabilities/view_source_all.php:18`. The code appears to be in top-level script scope, not a named function; Semgrep reports Function: `<unknown>`.
3. Step 3: No validation, sanitization, allowlist, or encoding is applied to `$id` before the flagged sink at line 18. The later `switch ($id)` starts at line 30, but it occurs after the file reads and therefore does not protect line 18. The new context did not reveal any upstream sanitizer because the requested contexts were unavailable.
4. Step 4: The sink is PHP `file_get_contents` at line 18. The operation is potentially dangerous because a user-controlled value is used in a filename/resource lookup. However, for the specific reported CWE-918 SSRF class, the constructed argument on line 18 is visibly prefixed with `./` and suffixed with `/source/medium.php`, so the attacker does not control the beginning of the filename where a PHP URL stream wrapper scheme such as `http://` would need to appear.
5. Step 5: No framework/library automatic protection is visible. The requested `function:dvwaPageStartup` context was unavailable, so its behavior cannot be relied on as a defense. The visible protection relevant to SSRF is not framework-based; it is the literal path construction `"./{$id}/source/medium.php"` at line 18, which forces a relative local path rather than a direct URL string.
6. Step 6: The visible code calls `dvwaPageStartup(array('authenticated'))` at line 6, suggesting an authenticated user is required. The implementation of `dvwaPageStartup` was unavailable, so exact authentication/authorization behavior is not visible.
7. Step 7: If `$id` is attacker-controlled, the visible security concern is local filename/path manipulation because `$id` is embedded into paths on lines 14, 18, 22, and 26. For the specific reported SSRF impact, the code does not clearly allow an attacker to cause a remote server-side request because the `file_get_contents` argument at line 18 cannot start with a remote URL scheme due to the fixed `./` prefix.
8. Step 8: The weakest link is the absence of validation or allowlisting before `$id` is used in file paths. However, for this Semgrep finding’s specific CWE-918 SSRF claim, the defense visible on the flagged path is the fixed relative path prefix `./` at line 18, which prevents direct use of attacker-controlled URL schemes as the filename.
