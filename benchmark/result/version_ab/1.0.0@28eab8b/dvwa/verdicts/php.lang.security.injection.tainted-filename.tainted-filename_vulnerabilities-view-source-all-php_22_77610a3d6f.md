# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** TP · **Confidence:** High (0.86) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is visible and directly uses attacker-controlled `$_GET['id']` as part of a filename passed to `file_get_contents()` with no visible validation before the sink. Although the visible exploit class is better described as tainted local file path/path traversal rather than clearly SSRF, the flagged sink is genuinely unsafe on the shown data flow.

## Data flow

HTTP GET parameter $_GET['id'] existence check (line 11) → direct assignment to $id (line 12) → interpolation into "./{$id}/source/high.php" (line 22) → file_get_contents() filename sink (line 22) → str_replace() on file contents (line 23) → highlight_string() for display (line 24). Additional requested context for dvwaPageStartup/dvwaPageNewGrab/DVWA_WEB_PAGE_TO_ROOT was unavailable and adds no visible sanitizer or guard.

## Answers

1. Step 0 / flagged line location: The flagged line is visible at line 22, exactly: `$highsrc = @file_get_contents("./{$id}/source/high.php");`. This is in the top-level script context of `vulnerabilities/view_source_all.php`; no named function or method wrapper is visible. The construct described by the rule is present on that line: a filename/path containing `$id` is passed to `file_get_contents()`.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP GET input. Line 11 checks for `id` in `$_GET`, and line 12 assigns `$id = $_GET['id'];`. The additional requested contexts for `dvwaPageStartup`, `dvwaPageNewGrab`, and `DVWA_WEB_PAGE_TO_ROOT` were unavailable, so they do not change this answer.
3. Step 2: Data flow is: `$_GET['id']` is checked for existence at line 11 → `$_GET['id']` is assigned directly to `$id` at line 12 → `$id` is interpolated into the filename string `"./{$id}/source/high.php"` at line 22 → that filename is passed to `file_get_contents()` at line 22 → the returned contents are assigned to `$highsrc` at line 22 → `$highsrc` is transformed by `str_replace()` at line 23 → `$highsrc` is passed to `highlight_string()` at line 24.
4. Step 3: No validation, sanitization, path canonicalization, basename enforcement, allowlist check, or traversal prevention is visible before the flagged sink at line 22. The `switch ($id)` begins at line 30, after the file reads on lines 14, 18, 22, and 26, so it cannot protect the flagged `file_get_contents()` call. The additional context was unavailable and provides no visible sanitizer.
5. Step 4: The sink is `file_get_contents()` on line 22. The dangerous operation is reading a server-side file path constructed from attacker-controlled `$id`. The Semgrep rule labels this as tainted filename/SSRF, but in the visible code the more concrete risk is tainted local filename/path traversal or unintended local file disclosure, because the attacker controls part of the path used for a file read.
6. Step 5: No automatic framework or library protection is visible. `file_get_contents()` does not automatically restrict paths to an intended directory. Line 6 calls `dvwaPageStartup(array('authenticated'))`, but the body was unavailable, and no visible code shows it validating `$_GET['id']` before line 22.
7. Step 6: Based on line 6, `dvwaPageStartup(array('authenticated'))`, the code path appears to require an authenticated user. No admin-only requirement is visible in the provided code.
8. Step 7: The concrete security impact is unintended server-side local file read/source disclosure for paths matching the constructed pattern `./<attacker-controlled>/source/high.php`. Because the contents are then processed by `str_replace()` and `highlight_string()` on lines 23-24, the read file content may be exposed in the response. Direct SSRF is less clearly supported by the visible string because the filename is prefixed with `./`, but the tainted file-read issue remains.
9. Step 8: The weakest link is the absence of any pre-sink allowlist or path validation for `$id`. The code appears to have intended valid IDs in the `switch ($id)` at lines 30-72, but that logic occurs after the file read and therefore does not defend the flagged sink.
