# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The sink is present at line 26, but the user-controlled `doc` parameter from line 20 is constrained to static `$docs` keys by the visible whitelist/fallback on lines 21-22. Therefore the attacker cannot supply an arbitrary filename or URL to `file_get_contents()` on the flagged path.

## Data flow

instructions.php:20 `$_GET['doc']` → instructions.php:20 `$selectedDocId` → instructions.php:21 `array_key_exists($selectedDocId, $docs)` whitelist check against static `$docs` from instructions.php:13-18 → instructions.php:22 fallback to `'readme'` for invalid keys → instructions.php:24 `$readFile = $docs[$selectedDocId]['file']`, selecting only hardcoded filenames → instructions.php:26 sink `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)`. Additional requested context for `dvwaPageStartup` and `DVWA_WEB_PAGE_TO_ROOT` was unavailable and adds no new visible data-flow step.

## Answers

1. Step 0 / flagged line: The flagged line is instructions.php:26: `$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );`. It is at PHP top-level script scope, not inside a visible named function; the supplied function label is `<unknown>`. The rule construct is present because `file_get_contents()` is called with a variable-derived filename expression.
2. Step 1: The only visible user-controlled source is `$_GET['doc']` at instructions.php:20. The additional requested context for `dvwaPageStartup` and `DVWA_WEB_PAGE_TO_ROOT` was unavailable, and it does not reveal any new source.
3. Step 2: Data flow remains: `$_GET['doc']` at line 20 → `$selectedDocId` at line 20 → validation with `array_key_exists($selectedDocId, $docs)` at line 21 → fallback assignment `$selectedDocId = 'readme'` at line 22 if invalid → `$readFile = $docs[$selectedDocId]['file']` at line 24 → `file_get_contents(DVWA_WEB_PAGE_TO_ROOT.$readFile)` at line 26.
4. Step 3: Yes, validation is visible. `$selectedDocId` is checked against the statically defined `$docs` whitelist at lines 13-18 using `array_key_exists()` on line 21. Invalid keys are replaced with `'readme'` on line 22. This is sufficient for the reported tainted-filename/SSRF class because the actual filenames are hardcoded values from lines 14-17, not attacker-provided arbitrary paths or URLs.
5. Step 4: The sink is `file_get_contents()` at line 26. The operation would be dangerous if an attacker controlled the filename or URL being read, because PHP file APIs can read local files and, depending on configuration, URL wrappers. In this visible path, attacker input controls only which whitelisted document key is selected.
6. Step 5: No framework or library automatic protection at the sink is visible. The requested `function:dvwaPageStartup` context was unavailable, so no startup framework protection can be confirmed. The relevant visible protection is application-level whitelisting at lines 21-22.
7. Step 6: The privilege/authentication state needed to trigger this code path remains not visible. Line 7 calls `dvwaPageStartup(array())`, but its body was unavailable. This does not affect whether the filename at line 26 is attacker-controlled in the shown code.
8. Step 7: If an attacker could control the argument to `file_get_contents()` on line 26, possible impact could include SSRF, local file disclosure, or denial of service. However, the visible code prevents arbitrary filename/URL control by limiting selection to the hardcoded files in `$docs` at lines 13-18.
9. Step 8: No exploitable weak link is visible for this rule. The defense is the whitelist of document IDs and fixed file mappings at lines 13-18, enforced by `array_key_exists()` and fallback on lines 21-22 before `$readFile` is used at line 26.
