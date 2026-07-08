# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

Although the flagged `file_get_contents` sink is present at line 26, the filename argument is not attacker-controlled on the visible path. The attacker-controlled `$_GET['doc']` value on line 20 is used only as a key into a hardcoded allowlist after explicit validation and fallback on lines 21-24, preventing arbitrary local filenames or remote URLs from reaching the sink.

## Data flow

source `$_GET['doc']` (instructions.php:20) → `$selectedDocId` assignment (instructions.php:20) → hardcoded `$docs` allowlist defined (instructions.php:13-18) → allowlist check `array_key_exists($selectedDocId, $docs)` and fallback to `'readme'` (instructions.php:21-23) → `$readFile = $docs[$selectedDocId]['file']` from hardcoded entries (instructions.php:24) → sink `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` (instructions.php:26). Additional requested contexts for `dvwaPageStartup`, `dvwaPageNewGrab`, `dvwaHtmlEcho`, and `DVWA_WEB_PAGE_TO_ROOT` were unavailable and add no new data.

## Answers

1. Step 0 / flagged line: The flagged line is line 26: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. The rule-described construct is present on that line: `file_get_contents(...)` is called with a filename expression containing `$readFile`. The code appears to live at top-level script scope in `instructions.php`; no named enclosing function is visible.
2. Step 1 / source: The only visible potentially dangerous source is user-controlled query input `$_GET['doc']` on line 20: `$selectedDocId = isset( $_GET[ 'doc' ] ) ? $_GET[ 'doc' ] : '';`.
3. Step 2 / trace: `$_GET['doc']` is assigned to `$selectedDocId` on line 20. `$selectedDocId` is checked against `$docs` on line 21. Invalid values are replaced with `'readme'` on line 22. `$readFile` is then assigned from `$docs[$selectedDocId]['file']` on line 24. `$readFile` is concatenated with `DVWA_WEB_PAGE_TO_ROOT` and passed to `file_get_contents` on line 26.
4. Step 3 / validation: Yes. Lines 13-18 define a hardcoded allowlist `$docs` whose keys map to fixed file paths. Lines 21-23 validate the user-selected key with `array_key_exists($selectedDocId, $docs)` and force a safe default `'readme'` when the key is absent. This is sufficient for the reported tainted-filename/SSRF issue because the filename used on line 26 can only be one of the hardcoded values from lines 14-17.
5. Step 4 / sink: The sink is line 26: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. `file_get_contents` can be dangerous if an attacker controls the filename or URL, because PHP may read local files or remote URLs depending on configuration. In this path, however, arbitrary attacker-controlled filenames are blocked by the allowlist.
6. Step 5 / framework/library protections: No relevant automatic framework or library protection is visible. The newly provided additional context for `dvwaPageStartup`, `dvwaPageNewGrab`, `dvwaHtmlEcho`, and `DVWA_WEB_PAGE_TO_ROOT` is unavailable, so it does not change the analysis. The decisive visible protection is explicit application-level allowlist validation on lines 13-24.
7. Step 6 / privilege/authentication: Not visible in provided context. Line 7 calls `dvwaPageStartup(array())`, but the implementation remains unavailable, so the required authentication state cannot be determined from the provided code. This does not affect whether the filename is attacker-controlled at line 26.
8. Step 7 / impact: If an attacker could control the `file_get_contents` argument, potential impact could include SSRF through URL wrappers or unauthorized local file reads. In the shown code, the attacker controls only the lookup key from `$_GET['doc']`, not the resulting filename, because invalid keys are replaced and valid keys map to hardcoded local paths.
9. Step 8 / weakest link: For the reported CWE-918 tainted-filename issue, no weak link is visible in the source-to-sink chain. The defense is complete in the shown code because user input is constrained to keys present in a hardcoded allowlist before any filename is selected.
