# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context was unavailable and does not change the visible analysis. Although line 26 is a filename sink, user input from `$_GET['doc']` is not used as the filename directly; it is constrained by a hardcoded whitelist on lines 21-23, so `$readFile` can only be one of the hardcoded paths defined on lines 14-17.

## Data flow

instructions.php:20 `$_GET['doc']` → instructions.php:20 `$selectedDocId` → instructions.php:21 whitelist check `array_key_exists($selectedDocId, $docs)` against hardcoded `$docs` from instructions.php:13-18 → instructions.php:22 fallback to `'readme'` for invalid input → instructions.php:24 `$readFile = $docs[$selectedDocId]['file']` selecting only hardcoded filenames → instructions.php:26 `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)`

## Answers

1. Step 0 / Locate flagged line: The exact flagged line is line 26 in `instructions.php`: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. The construct described by the rule is present on that line: `file_get_contents()` is called with a computed filename/path expression.
2. Step 1: The potentially dangerous data originates from user input: `$_GET['doc']` on line 20. The additional requested context was unavailable and does not reveal any new source.
3. Step 2: Data flow remains unchanged with the additional context: `$docs` is a fixed array of allowed document IDs and hardcoded filenames on lines 13-18; `$_GET['doc']` is assigned to `$selectedDocId` on line 20; `$selectedDocId` is checked against `$docs` using `array_key_exists()` on line 21; invalid values are replaced with `'readme'` on line 22; `$readFile` is assigned from `$docs[$selectedDocId]['file']` on line 24; `$readFile` is concatenated with `DVWA_WEB_PAGE_TO_ROOT` and passed to `file_get_contents()` on line 26.
4. Step 3: Yes, there is validation. Lines 21-23 implement a whitelist: only keys present in the hardcoded `$docs` array from lines 13-18 are accepted. If the attacker supplies any other `doc` value, `$selectedDocId` is reset to `'readme'` on line 22. This is sufficient for the flagged filename issue because the filename on line 24 can only be selected from hardcoded values on lines 14-17.
5. Step 4: The sink is `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` on line 26. This operation would be dangerous if the filename were attacker-controlled, because PHP file APIs may read local files or stream-wrapper URLs. Here, the visible path constrains `$readFile` to hardcoded entries.
6. Step 5: No framework or library automatic protection is visible. The requested body for `dvwaPageStartup()` and other callees was unavailable, so no framework-level protections can be credited. The relevant visible protection is the application-level whitelist on lines 21-23.
7. Step 6: The required authentication or privilege level remains not visible in the provided context. `dvwaPageStartup(array())` is called on line 7, but its implementation was unavailable. This does not affect exploitability of the flagged filename path because the filename is visibly whitelisted before the sink.
8. Step 7: If an attacker controlled the filename directly, possible impact could include local file disclosure or SSRF via `file_get_contents()` on line 26. In the shown code, the attacker can only choose among whitelisted document IDs mapping to hardcoded files: `README.md`, `docs/pdf.html`, `CHANGELOG.md`, and `COPYING.txt` on lines 14-17, so the flagged path does not provide arbitrary file/URL control.
9. Step 8: No weak link exists in the visible defense chain for this flagged sink. The complete defense is the whitelist check on lines 21-23 against the fixed `$docs` mapping on lines 13-18 before the filename is selected on line 24 and used at line 26.
