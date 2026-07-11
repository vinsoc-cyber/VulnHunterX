# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

Line 18 is materially the same untrusted-input-to-`file_get_contents()` construct as the confirmed sibling line 22, with only a different constant filename suffix and no added validation, sanitization, allowlist, or reachability restriction. Because the sibling establishes the attacker-reachable consequence in this file, the same vulnerable data flow applies to this flagged sink. [second-opinion pass: TP challenge on correctness rule]

## Answers

1. Step 0 / Locate flagged line: The exact flagged line is line 18: `$medsrc = @file_get_contents("./{$id}/source/medium.php");`. The reported construct is present: `file_get_contents()` is called with a path containing interpolated `$id`.
2. (a) This line is the same construct with the same untrusted input as the confirmed sibling(s). The source is `$_GET['id']`, checked at line 11 and assigned directly to `$id` at line 12. Line 18 uses `$id` in `file_get_contents()`, the same sink pattern as the sibling at line 22 (`$highsrc = @file_get_contents("./{$id}/source/high.php");`). The only visible difference is the constant filename segment: `medium.php` on line 18 versus `high.php` on line 22.
3. (b) This line adds no real defense that the sibling lacked. There is no validation, sanitization, allowlist, canonicalization, `basename()`, `realpath()` containment check, or conversion to a constant/non-attacker-controlled value before line 18. The `switch ($id)` beginning at line 30 occurs after the file read and therefore cannot protect the sink. The `@` at line 18 only suppresses errors. The different constant suffix `medium.php` is not a defense.
4. (c) This sink is not shown to be unreachable where the sibling is reachable. The same enclosing condition `if (array_key_exists("id", $_GET))` at line 11 controls all the file reads, including line 18 and the confirmed sibling line 22. Once `id` exists, execution reaches line 18 before line 22, so if the sibling is reachable, this line is also reachable.
5. Vulnerability class: Although the Semgrep rule describes SSRF via tainted filename, the concrete dangerous behavior visible here is attacker-controlled filename/path use in `file_get_contents()`, i.e. tainted local file/path traversal-style file read/source disclosure at the flagged sink.
6. Source: User-controlled query parameter `$_GET['id']` at lines 11-12.
7. Transformations/sanitization: `$_GET['id']` is assigned directly to `$id` at line 12, then interpolated into the filename at line 18. No pre-sink validation or sanitization is visible.
8. Sink: `file_get_contents("./{$id}/source/medium.php")` at line 18 reads a file path partly controlled by the attacker.
