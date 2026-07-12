# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** TP · **Confidence:** High (0.86) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not introduce any visible defense. The flagged line 18 clearly performs a server-side file read using request-controlled `$_GET['id']` with no pre-sink validation; although the CWE-918 SSRF framing is not the best fit due to the `./` prefix, the flagged sink is genuinely unsafe as tainted filename/path traversal.

## Data flow

vulnerabilities/view_source_all.php:11 checks array_key_exists('id', $_GET) → vulnerabilities/view_source_all.php:12 assigns $_GET['id'] to $id → vulnerabilities/view_source_all.php:18 interpolates $id into "./{$id}/source/medium.php" → vulnerabilities/view_source_all.php:18 passes the constructed path to file_get_contents()

## Answers

1. Step 0 / flagged line: The flagged line is present at vulnerabilities/view_source_all.php:18 and its exact text is `$medsrc = @file_get_contents("./{$id}/source/medium.php");`. The rule-described construct is present on that line: user-derived `$id` is interpolated into a filename passed to `file_get_contents()`. The code appears to live in top-level PHP script scope; the function is labeled `<unknown>` in the provided context.
2. Step 1: The dangerous data originates from HTTP request input, specifically `$_GET['id']`. The key is checked for existence at line 11, then the value is assigned to `$id` at line 12.
3. Step 2: The data flow is: `$_GET['id']` existence check at line 11 → direct assignment `$id = $_GET['id'];` at line 12 → interpolation into the path string `"./{$id}/source/medium.php"` at line 18 → passed to `file_get_contents()` at line 18. The same `$id` is also used in sibling file reads at lines 14, 22, and 26, but the flagged sink is specifically line 18.
4. Step 3: No validation, sanitization, canonicalization, allowlist, `basename()`, regex restriction, or safe path join is visible before line 18. The only pre-sink check is `array_key_exists("id", $_GET)` at line 11, which confirms presence but does not restrict content. The `switch ($id)` starting at line 30 contains apparent known IDs, but it occurs after the file reads, so it does not protect the flagged sink.
5. Step 4: The sink is `file_get_contents()` at line 18. The dangerous operation is server-side filesystem access using a path component controlled by the request. The rule describes SSRF from tainted filenames; in this specific line, direct SSRF is less clear because the constructed path begins with `./`, but the sink is still unsafe as a tainted local filename/path traversal read.
6. Step 5: No automatic framework/library protection is visible at the sink. The additional requested context for `dvwaPageStartup` and `dvwaPageNewGrab` was unavailable, so it does not change the previous analysis. `dvwaPageStartup(array('authenticated'))` at line 6 suggests authentication, but no visible file-path validation or sandboxing.
7. Step 6: Based on the visible line 6 call to `dvwaPageStartup(array('authenticated'))`, an attacker likely needs to be authenticated. No admin-only requirement is visible in the provided code.
8. Step 7: If an authenticated attacker controls `$id`, they can cause the server to attempt to read a path outside the intended set of vulnerability directories by using traversal sequences in the `$id` path component. The concrete impact is unauthorized local file/source disclosure where a reachable path can be made to match the fixed suffix `/source/medium.php`; direct SSRF is not clearly demonstrated because of the `./` prefix.
9. Step 8: The weakest link is direct use of `$_GET['id']` as a filesystem path component before any allowlist or canonical path check. A complete defense would require validating `$id` against known safe values before line 18 or resolving the path and enforcing that it remains under an intended base directory.
