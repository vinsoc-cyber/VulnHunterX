# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The reported sink is a filename read at line 26, but the filename is not directly controlled by `$_GET['doc']`; user input is first constrained to exact keys of the hardcoded `$docs` whitelist on lines 13-22. The additional requested context was unavailable and does not reveal any path that bypasses this visible whitelist defense.

## Data flow

instructions.php:20 $_GET['doc'] → instructions.php:20 $selectedDocId → instructions.php:21 whitelist check array_key_exists($selectedDocId, $docs) → instructions.php:22 invalid values replaced with hardcoded 'readme' → instructions.php:24 $readFile = $docs[$selectedDocId]['file'] from hardcoded $docs entries on lines 13-18 → instructions.php:26 file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile), with DVWA_WEB_PAGE_TO_ROOT visibly defined as '' on line 3

## Answers

1. Step 1: The potentially dangerous data originates from user-controlled query parameter `$_GET['doc']` on line 20. The additional context for `dvwaPageStartup` and `DVWA_WEB_PAGE_TO_ROOT` was unavailable and does not change this source identification.
2. Step 2: Data flow: `$_GET['doc']` is assigned to `$selectedDocId` on line 20; `$selectedDocId` is checked against the hardcoded `$docs` whitelist using `array_key_exists($selectedDocId, $docs)` on line 21; if the key is not present, `$selectedDocId` is replaced with the hardcoded value `'readme'` on line 22; `$readFile` is assigned from `$docs[$selectedDocId]['file']` on line 24; `$readFile` is concatenated with `DVWA_WEB_PAGE_TO_ROOT`, which is visibly defined as the empty string on line 3, and passed to `file_get_contents()` on line 26.
3. Step 3: Yes. Validation occurs on lines 21-22: the user-controlled document ID must exactly match one of the hardcoded keys in `$docs` from lines 13-18. If it does not, it is reset to `'readme'`. This is sufficient for the reported tainted-filename/SSRF issue because the eventual filename on line 26 can only be one of the hardcoded local file paths in `$docs`, not an arbitrary user-supplied URL or path.
4. Step 4: The sink is line 26: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. The dangerous operation is reading a file or URL-like stream via `file_get_contents()`. It would be unsafe if attacker-controlled input reached the filename argument, but here `$readFile` is selected from a fixed whitelist.
5. Step 5: No framework or library automatic protection at `file_get_contents()` is visible or needed for this specific flow. The requested `function:dvwaPageStartup` context was unavailable, so no framework protection can be credited from it. The concrete visible defense is the whitelist check on lines 21-22 combined with the hardcoded `$docs` array on lines 13-18.
6. Step 6: The privilege or authentication level needed to reach the page is not visible in the provided context. `dvwaPageStartup(array())` is called on line 7, but its implementation remains unavailable. This does not affect whether the filename argument is attacker-controlled on the flagged path.
7. Step 7: If an attacker controlled the argument to `file_get_contents()` on line 26, the potential impact could include SSRF via PHP URL wrappers or local file disclosure via arbitrary paths. In the visible code, that impact is prevented because attacker input only selects among hardcoded local entries: `README.md`, `docs/pdf.html`, `CHANGELOG.md`, or `COPYING.txt` on lines 14-17.
8. Step 8: No weak link exists for the reported tainted-filename/SSRF chain in the provided code. The defense is complete for this path because user input on line 20 is constrained by an explicit hardcoded whitelist on lines 13-22 before the filename is selected on line 24 and used at the sink on line 26.
