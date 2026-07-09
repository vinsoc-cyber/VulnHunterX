# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is a real file-read sink, but the attacker-controlled `doc` parameter does not flow into it as an arbitrary filename. The visible whitelist on lines 21-23 constrains `$selectedDocId` to keys of the static `$docs` array, so `$readFile` on line 24 can only be one of the hard-coded paths from lines 14-17 before reaching `file_get_contents` on line 26.

## Data flow

instructions.php:20 source `$_GET['doc']` → instructions.php:20 `$selectedDocId` → instructions.php:21 whitelist check `array_key_exists($selectedDocId, $docs)` against static `$docs` from lines 13-18 → instructions.php:22 invalid values replaced with `'readme'` → instructions.php:24 `$readFile = $docs[$selectedDocId]['file']` where values are fixed literals from lines 14-17 → instructions.php:26 sink `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` with `DVWA_WEB_PAGE_TO_ROOT` defined as `''` on line 3

## Answers

1. Step 0 / flagged line location: The exact flagged line is line 26: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. The reported construct is present on that line: `file_get_contents(...)` is used with a filename/path expression. The code is in top-level PHP script scope in `instructions.php`; the provided function label is `Function: <unknown>`.
2. Step 1 / source: The potentially dangerous user-controlled input originates from the HTTP query parameter `$_GET['doc']` on line 20. No other user-controlled source for the filename is visible in the provided code.
3. Step 2 / trace: `$_GET['doc']` is assigned to `$selectedDocId` on line 20 if present, otherwise `''` is used. `$selectedDocId` is checked with `array_key_exists($selectedDocId, $docs)` on line 21. If the key is not present in `$docs`, `$selectedDocId` is reset to the literal safe default `'readme'` on line 22. `$readFile` is then assigned from `$docs[$selectedDocId]['file']` on line 24. Finally, `$readFile` is concatenated with the constant `DVWA_WEB_PAGE_TO_ROOT`, defined as `''` on line 3, and passed to `file_get_contents(...)` on line 26.
4. Step 3 / validation, sanitization, encoding: Yes. The validation is a whitelist check on lines 21-23 against the locally defined `$docs` array on lines 13-18. The only possible file values after this check are the hard-coded literals `README.md`, `docs/pdf.html`, `CHANGELOG.md`, and `COPYING.txt` from lines 14-17. This is sufficient for the flagged tainted-filename/SSRF-style issue because attacker input selects only a whitelisted document ID and cannot become an arbitrary local path or remote URL.
5. Step 4 / sink: The sink is `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` on line 26. This operation would be dangerous if `$readFile` were attacker-controlled because PHP file functions may read local files and, depending on configuration, remote stream wrappers. In this path, however, `$readFile` is derived from fixed whitelisted values.
6. Step 5 / framework or library protections: No framework/library automatic protection is visible or necessary at the flagged sink. The requested additional context for `dvwaPageStartup`, `dvwaPageNewGrab`, and global `DVWA_WEB_PAGE_TO_ROOT` was unavailable, so it does not change the analysis. The relevant visible protection is the explicit whitelist using `$docs` on lines 13-18 and `array_key_exists` on line 21.
7. Step 6 / privilege or authentication state: The required authentication state is not visible in the provided code. The script calls `dvwaPageStartup(array())` on line 7, but its body was unavailable in the added context. An attacker would at least need the ability to request this page with a `doc` query parameter.
8. Step 7 / concrete impact if controlled: If an attacker could control the argument to `file_get_contents`, the impact could be local file disclosure, path traversal, or SSRF through PHP stream wrappers. In the shown code, this impact is prevented because the filename passed to the sink is selected only from hard-coded whitelist entries.
9. Step 8 / weakest link: No exploitable weak link is visible for this flagged data flow. The defense is complete in the provided code because the user-controlled value is validated as a key in a static local map before the filename is selected, and invalid input is forced to `'readme'` on line 22.
