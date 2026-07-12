# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged `file_get_contents()` sink is present at line 26, but the user-controlled `$_GET['doc']` value is constrained by a visible allowlist check against the hard-coded `$docs` array on lines 13-22 before `$readFile` is selected on line 24. Since the final filename can only be one of the fixed local filenames on lines 14-17, arbitrary filename/URL control required for SSRF or file disclosure is prevented.

## Data flow

source `$_GET['doc']` (instructions.php:20) → assigned to `$selectedDocId` (instructions.php:20) → validated by `array_key_exists($selectedDocId, $docs)` against hard-coded `$docs` keys (instructions.php:13-18, 21) → invalid key overwritten with `'readme'` (instructions.php:22) → `$readFile` assigned from `$docs[$selectedDocId]['file']` (instructions.php:24) → sink `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` (instructions.php:26). Additional requested context for `global:DVWA_WEB_PAGE_TO_ROOT` and `function:dvwaPageStartup` was unavailable and adds no new data.

## Answers

1. Step 0 / flagged line location: The exact flagged line is instructions.php:26: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. The rule-described construct is present on that line: `file_get_contents()` is called with a filename/path expression.
2. Step 1: The potentially dangerous input originates from the HTTP query string: `$_GET['doc']` at instructions.php:20. The additional context for `global:DVWA_WEB_PAGE_TO_ROOT` and `function:dvwaPageStartup` was unavailable and does not change this source identification.
3. Step 2: The data flow is: `$_GET['doc']` at line 20 → `$selectedDocId` at line 20 → allowlist check with `array_key_exists($selectedDocId, $docs)` at line 21 → invalid values replaced by `'readme'` at line 22 → `$readFile = $docs[$selectedDocId]['file']` at line 24 → `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` at line 26. The `$docs` array is locally defined with hard-coded entries on lines 13-18.
4. Step 3: Yes. There is explicit validation at line 21: `if( !array_key_exists( $selectedDocId, $docs ) )`. If the user-supplied key is not one of the hard-coded keys in `$docs`, it is overwritten with `'readme'` on line 22. This is sufficient for the filename/SSRF issue because `$readFile` can only come from the fixed filenames in lines 14-17: `README.md`, `docs/pdf.html`, `CHANGELOG.md`, or `COPYING.txt`.
5. Step 4: The sink is `file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile )` on line 26. This operation would be dangerous if an attacker controlled the final filename or URL, because `file_get_contents()` can read local files and may fetch remote resources depending on PHP configuration. In the visible code, the attacker does not control the final filename.
6. Step 5: No automatic framework or library protection for `file_get_contents()` is visible. The additional context for `dvwaPageStartup()` was unavailable, but it is not needed to decide this finding because the visible application-level allowlist on lines 21-22 protects the flagged filename sink.
7. Step 6: The privilege/authentication state required to reach this page remains not visible. Line 7 calls `dvwaPageStartup(array())`, but its body was not provided. This does not change the exploitability analysis for the flagged sink because even a reachable attacker can only select an allowlisted document ID.
8. Step 7: If the attacker could control `$readFile`, the potential impact would be arbitrary local file read or SSRF. However, because `$readFile` is selected only from hard-coded values in `$docs` after the line 21 allowlist, the concrete security impact is not realized on this path.
9. Step 8: No weak link exists in the visible defense chain for the flagged sink. The defense is the complete allowlist: user input chooses only a key, the key must exist in the hard-coded `$docs` array, invalid input is replaced with `'readme'`, and the sink receives only a fixed filename.
