# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** FP · **Confidence:** High (0.87) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

User input reaches `file_get_contents()` on line 22, but the reported vulnerability class is SSRF and the visible filename argument has a hardcoded `./` prefix before `$id`, preventing the attacker from supplying a leading URL-wrapper scheme. The code lacks validation and may merit separate review for local filename/path issues, but the specific CWE-918 SSRF finding is not clearly exploitable on the flagged path.

## Data flow

HTTP query parameter `$_GET['id']` in `vulnerabilities/view_source_all.php` lines 11-12 → assigned unchanged to `$id` on line 12 → no visible validation before sink → interpolated into local relative path `./{$id}/source/high.php` on line 22 → passed to `file_get_contents()` on line 22. Requested additional context was unavailable and adds no new data to this flow.

## Answers

1. Step 0 / flagged line: The flagged line is line 22: `$highsrc = @file_get_contents("./{$id}/source/high.php");`. The construct described by the rule is present on that line: a filename/path passed to `file_get_contents()` contains interpolated variable `$id`.
2. Function location: The provided code context identifies the function as `<unknown>`. The snippet appears to be top-level PHP code in `vulnerabilities/view_source_all.php`, not a visible named function or method.
3. Step 1: The potentially dangerous data originates from HTTP query string user input. The code checks `array_key_exists("id", $_GET)` on line 11 and assigns `$_GET['id']` to `$id` on line 12.
4. Step 2: The visible data flow is: `$_GET['id']` at lines 11-12 → assignment to `$id` on line 12 → interpolation into the filename string `"./{$id}/source/high.php"` on line 22 → passed to `file_get_contents()` on line 22. The additional requested context for `dvwaPageStartup`, `dvwaPageNewGrab`, `$_GET`, and `php.ini` was unavailable, so it does not change this trace.
5. Step 3: No explicit validation, sanitization, allowlist, canonicalization, or encoding of `$id` is visible before line 22. However, for the specific reported CWE-918 SSRF class, line 22 constructs the filename with a literal `./` prefix before attacker-controlled `$id`, so `$id` cannot occupy the leading position required to form a PHP URL-wrapper scheme such as `http://`, `https://`, or `ftp://`.
6. Step 4: The sink is `file_get_contents()` on line 22. The dangerous operation would be server-side fetching of an attacker-controlled URL if the filename argument could be made to start with a remote stream wrapper scheme. In the shown code, the argument starts with the literal relative path prefix `./`, so the user input is embedded inside a local relative path rather than used as the leading URL.
7. Step 5: No automatic framework or library SSRF protection is visible. The additional requested context for `dvwaPageStartup` and `dvwaPageNewGrab` is unavailable. The visible protection relevant to the reported SSRF issue is the hardcoded local-path prefix `./` on line 22.
8. Step 6: The code calls `dvwaPageStartup(array('authenticated'))` on line 6, so the visible context indicates the path is intended for authenticated users. The implementation of `dvwaPageStartup` is unavailable, so the exact authentication enforcement is not visible.
9. Step 7: If the attacker could control a full URL passed to `file_get_contents()`, the impact could be SSRF, potentially allowing server-side requests to internal or external resources. In this specific flagged line, that impact is not demonstrated because the attacker-controlled value is not placed where it can define the URL scheme. A separate local path traversal or unintended file-read concern may exist due to unsanitized `$id`, but that is not the reported CWE-918 SSRF finding.
10. Step 8: The weakest visible link is the absence of validation or allowlisting for `$id` before it is used in filesystem paths. For the specific SSRF defense chain, however, the critical visible defense is that line 22 prepends `./` before `$id`, preventing a user-controlled URL scheme from being passed directly to `file_get_contents()`.
