# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source.php:63

**Verdict:** TP · **Confidence:** High (0.86) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 4

## Reasoning

The flagged sink is present at line 63, and user-controlled `$_GET['security']` from line 13 reaches `file_get_contents` without any visible validation or path restriction. This is a real tainted-filename/path traversal-style file disclosure issue at the flagged sink, even if the exact CWE-918 SSRF framing is not the most precise impact.

## Data flow

HTTP GET input `$_GET['security']` (line 13) → assigned to `$security` (line 13) → no visible validation/sanitization (lines 13-63) → interpolated into `DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php"` (line 63) → server-side file read via `file_get_contents(...)` (line 63) → contents rendered with `highlight_string($source, true)` (line 89)

## Answers

1. Step 0 / Flagged line: The flagged line is present at line 63: `$source = @file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php" );`. This line contains the reported construct: a variable-derived filename is passed to PHP `file_get_contents`.
2. Step 1 / Source: The dangerous data originates from user-controlled HTTP GET input at line 13: `$security = $_GET[ 'security' ];`. `$id` is also used in the filename at line 63, but its source is not visible in the provided code.
3. Step 2 / Trace: `$_GET['security']` is assigned to `$security` on line 13. `$security` is then interpolated directly into the path string on line 63 as `{$security}.php`. That full path is passed to `file_get_contents` on line 63. `$id` is used in a `switch` at lines 16-61 to set `$vuln`, and is also interpolated into the path on line 63, but its source is not visible.
4. Step 3 / Validation/Sanitization: No validation, sanitization, allowlist, path normalization, `basename`, `realpath`, or canonical directory check is visible for `$security` between line 13 and line 63. The `switch ($id)` at lines 16-61 only maps `$id` to a display label `$vuln`; the default case at lines 59-60 does not reject execution.
5. Step 4 / Sink: The sink is line 63, where `file_get_contents` reads a server-side file path constructed with user-controlled `$security`. The unsafe operation is filesystem read using attacker-influenced filename/path data.
6. Step 5 / Framework/Library Protections: No framework protection is visible. PHP `file_get_contents` does not automatically prevent path traversal or restrict filenames. The `@` operator on line 63 only suppresses errors and is not a security defense.
7. Step 6 / Required Privilege/Auth State: Not visible in the provided context. The snippet does not show whether this page requires authentication or a particular role.
8. Step 7 / Security Impact: If an attacker controls `$security`, they can influence which server-side `.php` file is read and then displayed via `highlight_string($source, true)` at line 89. The concrete visible impact is unauthorized local file/source disclosure or path traversal-style file read. SSRF is less clearly established because the path is prefixed with `DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/"`, but the flagged tainted-filename risk is real.
9. Step 8 / Weakest Link: The weakest link is the direct flow from `$_GET['security']` at line 13 into `file_get_contents` at line 63 without any visible allowlist or canonical path enforcement. No complete defense is visible in the provided code or additional context.
