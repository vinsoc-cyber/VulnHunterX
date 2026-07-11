# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

Line 14 is materially the same untrusted-input-to-`file_get_contents` construct as the confirmed True Positive sibling, with only a different constant filename suffix and no added validation or reachability difference. The same authenticated attacker-controlled `$id` reaches the same kind of server-side file access sink before any visible allowlist or sanitization. [second-opinion pass: TP challenge on correctness rule]

## Answers

1. Step 0 / flagged line: The flagged line is present at line 14 and is exactly: `$lowsrc = @file_get_contents("./{$id}/source/low.php");`. The rule-described construct is present on this line: `$id` is interpolated into a filename/path passed to `file_get_contents`.
2. Step 1: The dangerous data originates from user-controlled HTTP query input. Line 11 checks for the `id` key in `$_GET`, and line 12 assigns `$_GET['id']` directly to `$id`.
3. Step 2: Data flow is: `$_GET['id']` on line 12 → assigned directly to `$id` on line 12 → interpolated into `"./{$id}/source/low.php"` on line 14 → passed to `file_get_contents` on line 14.
4. Step 3: No validation, sanitization, canonicalization, allowlist, or encoding is applied to `$id` before line 14. The `switch ($id)` beginning on line 30 occurs after the file reads on lines 14, 18, 22, and 26, so it does not protect the flagged sink.
5. Step 4: The sink is `file_get_contents("./{$id}/source/low.php")` on line 14. The dangerous operation is server-side file access using a path constructed from attacker-controlled input.
6. Step 5: No framework or library automatic protection is visible before the sink. `file_get_contents` does not provide an application allowlist or path traversal protection, and no upstream framework validation is visible in the provided code before line 14.
7. Step 6: The code calls `dvwaPageStartup(array('authenticated'))` on line 6, so the visible requirement is that the attacker must be authenticated. No admin-only requirement is visible.
8. Step 7: The concrete impact is attacker-influenced server-side file access/source disclosure through a tainted filename sink. The sibling finding on the same construct in this file was confirmed True Positive, establishing that the attacker-reachable consequence is real in this file.
9. Step 8: The weakest link is the direct use of `$id` from `$_GET` in a filesystem read before any validation or allowlist. There is no complete defense visible on the flagged path.
10. (a) This line is the same construct with the same untrusted input as the confirmed sibling(s). Line 14 uses `$id` from `$_GET['id']` line 12 in `file_get_contents`, just as the sibling at line 22 uses the same `$id` in the same kind of sink. The only visible difference is the constant suffix/path segment: `low.php` on line 14 versus `high.php` on line 22.
11. (b) This line does not add any real defense the sibling lacked. There is no validation, sanitization, allowlist, canonicalization, or constant/non-attacker-controlled replacement for `$id` before line 14. The different literal filename `low.php` is not a security defense.
12. (c) This sink is not genuinely unreachable where the sibling is reachable. Lines 14, 18, 22, and 26 are all inside the same `if (array_key_exists("id", $_GET))` block beginning on line 11, and line 14 is reached earlier than the sibling line 22 on the same path.
