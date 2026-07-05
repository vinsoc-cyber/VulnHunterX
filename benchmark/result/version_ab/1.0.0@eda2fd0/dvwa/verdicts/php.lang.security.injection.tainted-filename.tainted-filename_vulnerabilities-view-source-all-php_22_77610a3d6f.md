# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** FP · **Confidence:** High (0.87) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The reported rule is specifically SSRF via tainted filename, but the flagged `file_get_contents` argument on line 22 always begins with the literal relative path prefix `./` before user input. Since PHP URL wrappers require the scheme at the beginning of the filename, the shown path construction prevents the attacker-controlled `id` from becoming an SSRF URL, despite the absence of an explicit allowlist.

## Data flow

Source: `$_GET['id']` in `vulnerabilities/view_source_all.php` line 12 → assignment: `$id = $_GET['id']` on line 12 → sink: `$highsrc = @file_get_contents("./{$id}/source/high.php");` on line 22. Additional requested context for `dvwaPageStartup` and `$_GET` was unavailable and does not alter the visible source-to-sink chain.

## Answers

1. Step 1: The potentially dangerous data originates from user-controlled HTTP query input: `$_GET['id']` is checked on line 11 and assigned to `$id` on line 12. The additional requested context for `global:$_GET` was unavailable, so nothing changes this source assessment.
2. Step 2: Data flow remains: `$_GET['id']` on line 12 → direct assignment to `$id` on line 12 → interpolation into filename arguments to `file_get_contents` on lines 14, 18, 22, and 26. The exact flagged line is line 22: `$highsrc = @file_get_contents("./{$id}/source/high.php");`. The code appears to live in top-level script scope in `vulnerabilities/view_source_all.php`, function `<unknown>`.
3. Step 3: No explicit validation, sanitization, or allowlist of `$id` is visible before the file reads on lines 14, 18, 22, and 26. The later `str_replace` and `highlight_string` calls on lines 15-16, 19-20, 23-24, and 27-28 occur after the file read and do not sanitize the filename. However, for the specific CWE-918 SSRF class, the filename argument has a literal `./` prefix before attacker-controlled `$id`, including at line 22, which prevents the final filename from beginning with a URL scheme such as `http://` or `https://`.
4. Step 4: The sink is `file_get_contents` using a tainted filename, specifically the flagged line 22: `$highsrc = @file_get_contents("./{$id}/source/high.php");`. The dangerous operation for this rule would be PHP treating the filename as a remote URL/stream wrapper and making a server-side request. In the shown code, the argument starts with `./`, so the attacker does not control the start of the string where a PHP URL wrapper scheme must appear.
5. Step 5: No framework-provided filename validation is visible. The requested body of `dvwaPageStartup` was unavailable, so no framework protection can be credited from that function. The relevant visible protection for the SSRF-specific issue is the PHP filename construction itself: a literal relative-path prefix `./` is prepended before `$id` at the sink on line 22.
6. Step 6: The visible code calls `dvwaPageStartup(array('authenticated'))` on line 6, suggesting authenticated access is intended. The implementation of `dvwaPageStartup` was unavailable, so the exact privilege enforcement is not fully visible. No admin-only requirement is visible.
7. Step 7: If exploitable as reported, the impact would be SSRF: causing the server to fetch attacker-controlled external or internal network resources through `file_get_contents`. In this specific snippet, that SSRF impact is not supported because the tainted value cannot make the filename begin with a remote URL scheme due to the literal `./` prefix. A separate local path traversal/source disclosure concern may exist, but that is not the reported CWE-918 issue.
8. Step 8: The weakest visible defense is the lack of explicit allowlist validation for `$id`. For the reported SSRF issue, though, the decisive defense is that the attacker-controlled data is embedded after `./` and before `/source/high.php`, so it cannot form a URL-style filename at the flagged sink.
