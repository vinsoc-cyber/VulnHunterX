# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** TP · **Confidence:** High (0.88) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The exact flagged line is visible and contains a `file_get_contents` call using a filename built from `$_GET['id']` with no visible pre-sink validation, canonicalization, or allowlist. Although the rule describes SSRF, the exploitable issue shown at this sink is tainted filename/path traversal or local file/source disclosure, and the unavailable additional context provides no specific defense that would make this a false positive.

## Data flow

source `$_GET['id']` in `vulnerabilities/view_source_all.php` checked for existence (line 11) → assigned directly to `$id` (line 12) → `$id` interpolated into `"./{$id}/source/low.php"` (line 14) → sink `file_get_contents(...)` reads that attacker-influenced path (line 14) → post-sink content transformations `str_replace` (line 15) and `highlight_string` (line 16)

## Answers

1. Step 1: The dangerous data originates from user-controlled HTTP query input. Line 11 checks `array_key_exists("id", $_GET)`, and line 12 assigns `$id = $_GET['id'];`. The additional requested context for `dvwaPageStartup` and `dvwaPageNewGrab` is unavailable, so it does not change this source analysis.
2. Step 2: The visible data flow is direct: `$_GET['id']` on line 12 is assigned to `$id`, then `$id` is interpolated into the filename string on line 14. The exact flagged line is line 14: `$lowsrc = @file_get_contents("./{$id}/source/low.php");`. This is in the top-level script scope of `vulnerabilities/view_source_all.php`; the provided function label remains `<unknown>`. After the file is read, `$lowsrc` is transformed by `str_replace` on line 15 and `highlight_string` on line 16, but those happen after the filename has already been used.
3. Step 3: No validation, sanitization, canonicalization, allowlist, or encoding is visible before the sink on line 14. The `switch ($id)` beginning on line 30 contains known IDs, but it occurs after file reads on lines 14, 18, 22, and 26, so it cannot protect the flagged line. The additional context for `dvwaPageStartup` and `dvwaPageNewGrab` was unavailable and therefore provides no visible defense.
4. Step 4: The sink is `file_get_contents` on line 14. The dangerous operation is using attacker-controlled `$id` as part of a server-side filename/path: `"./{$id}/source/low.php"`. The rule message names SSRF, but from the visible path shape the clearer vulnerability at the flagged sink is tainted filename/path traversal leading to unauthorized local file read or source disclosure.
5. Step 5: No framework or library automatic protection is visible at this point. PHP `file_get_contents` does not automatically constrain interpolated paths to safe directories or enforce an allowlist. Line 6 calls `dvwaPageStartup(array('authenticated'))`, but its implementation is unavailable and there is no visible evidence that it sanitizes `$_GET['id']` before line 14.
6. Step 6: Based on visible code, an attacker must be authenticated because line 6 calls `dvwaPageStartup(array('authenticated'))`. No admin-only requirement is visible. The unavailable helper context does not change this assessment.
7. Step 7: If an authenticated attacker controls `id`, they can influence the path read by `file_get_contents` on line 14. The concrete impact is unauthorized local file/source disclosure for paths that can be made to match the constructed pattern `./<attacker-controlled>/source/low.php`; related reads at lines 18, 22, and 26 use the same tainted `$id` pattern for other filenames. SSRF is not clearly demonstrated by the visible relative-prefix path, but the flagged sink is still dangerous as a tainted filename/local file read issue.
8. Step 8: The single weakest link is the direct interpolation of `$_GET['id']` into the file path on line 14 before any visible validation or allowlisting. No complete defense is visible; the later `switch ($id)` at line 30 is too late to protect the file read.
