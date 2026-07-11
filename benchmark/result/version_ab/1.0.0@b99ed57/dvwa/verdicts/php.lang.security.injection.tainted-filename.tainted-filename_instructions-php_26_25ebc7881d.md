# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is present at line 26, but the filename passed to `file_get_contents()` is not directly attacker-controlled. The visible code provides a concrete defense: `$_GET['doc']` is restricted to hardcoded `$docs` keys on lines 21-23, and `$readFile` is selected only from hardcoded file path literals on lines 14-17.

## Data flow

instructions.php:3 `define('DVWA_WEB_PAGE_TO_ROOT', '')` + instructions.php:13-18 hardcoded `$docs` file map; source instructions.php:20 `$_GET['doc']` → instructions.php:20 `$selectedDocId` → instructions.php:21 `array_key_exists($selectedDocId, $docs)` allowlist check → instructions.php:22 fallback to `'readme'` if invalid → instructions.php:24 `$readFile = $docs[$selectedDocId]['file']` from hardcoded values → instructions.php:26 sink `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)`

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 26 and reads exactly: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. It is in top-level script scope in `instructions.php`, not inside a named function. The construct described by the rule is present: a filename/path expression is passed to `file_get_contents()`.
2. Step 1: The potentially dangerous data originates from user input in `$_GET['doc']` on line 20. The additional requested context for `dvwaPageStartup`, `dvwaPageNewGrab`, `dvwaHtmlEcho`, and `DVWA_WEB_PAGE_TO_ROOT` was unavailable, so it does not change this source analysis.
3. Step 2: Data flow with all visible context: `DVWA_WEB_PAGE_TO_ROOT` is defined as the empty string on line 3; `$docs` is initialized as a hardcoded array of allowed document IDs and hardcoded file paths on lines 13-18; `$selectedDocId` is assigned from `$_GET['doc']` or `''` on line 20; `$selectedDocId` is checked against `$docs` with `array_key_exists()` on line 21; invalid values are replaced with `'readme'` on line 22; `$readFile` is assigned from `$docs[$selectedDocId]['file']` on line 24; `$readFile` is concatenated with `DVWA_WEB_PAGE_TO_ROOT` and passed to `file_get_contents()` on line 26.
4. Step 3: Yes, there is validation. Lines 21-23 implement an allowlist: only keys present in the hardcoded `$docs` array from lines 13-18 are accepted. Otherwise, `$selectedDocId` is reset to `'readme'` on line 22. This is sufficient for the flagged tainted-filename path because the attacker controls only the selector, while the filename values used at line 24 are fixed literals from lines 14-17.
5. Step 4: The sink is `file_get_contents()` on line 26. The dangerous operation is reading a file path built from `DVWA_WEB_PAGE_TO_ROOT.$readFile`. If `$readFile` were attacker-controlled, this could permit local file read, path traversal, SSRF through URL wrappers, or denial of service. In the visible code, `$readFile` is selected from hardcoded allowlisted entries only.
6. Step 5: No framework or library automatic protection is visible at the sink. The additional context for `dvwaPageStartup()`, `dvwaPageNewGrab()`, and `dvwaHtmlEcho()` is unavailable and does not provide any new protection. The relevant visible protection remains the explicit allowlist check on lines 21-23.
7. Step 6: The privilege or authentication state required to reach this script is not visible in the provided context. `dvwaPageStartup(array())` is called on line 7, but its body remains unavailable. This does not affect whether the filename at the flagged sink is attacker-controlled.
8. Step 7: If an attacker could control the filename at line 26, the impact could include arbitrary local file read, path traversal, SSRF if PHP URL wrappers are enabled, or DoS. However, based on the visible path, the attacker cannot supply an arbitrary filename because line 21 validates the selector against the fixed `$docs` keys and line 24 retrieves only hardcoded file values.
9. Step 8: No exploitable weak link is visible in the defense chain for the flagged sink. The defense is complete for this data path because `$_GET['doc']` controls only a document ID, and the code enforces membership in the hardcoded `$docs` allowlist before selecting `$readFile`.
