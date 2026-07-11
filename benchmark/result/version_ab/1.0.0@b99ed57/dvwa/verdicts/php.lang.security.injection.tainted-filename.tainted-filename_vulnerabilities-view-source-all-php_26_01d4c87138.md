# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:26

**Verdict:** FP · **Confidence:** Low (0.4) · **Truth:** real · **Grade:** MISS · **Iterations:** 6

## Reasoning

Although user-controlled input reaches `file_get_contents()` on the flagged line without visible validation, the reported SSRF consequence is not concretely reachable because the filename begins with the literal relative prefix `./`, preventing the attacker from supplying a URL scheme as the fetched resource. Based on the available evidence and required final choice, the balance leans False Positive for this SSRF finding, while acknowledging a low-confidence residual local-path concern that is not concretely proven here.

## Answers

1. Step 0 / flagged line location: The flagged line is present at vulnerabilities/view_source_all.php:26. Exact text: `$impsrc = @file_get_contents("./{$id}/source/impossible.php");`. It appears to be in top-level PHP script scope, with the provided function listed as `<unknown>`.
2. Step 1: The potentially dangerous data originates from HTTP query-string user input: the presence of `id` is checked in `$_GET` on line 11, and `$_GET['id']` is assigned to `$id` on line 12.
3. Step 2: Data flow: `$_GET['id']` on line 12 → direct assignment to `$id` on line 12 → interpolation into the filename string `"./{$id}/source/impossible.php"` on line 26 → passed to `file_get_contents()` on line 26 → result assigned to `$impsrc` on line 26 → post-read processing by `str_replace()` on line 27 and `highlight_string()` on line 28.
4. Step 3: No explicit validation, sanitization, canonicalization, or allowlist check is visible before the sink on line 26. The `switch ($id)` on lines 30-75 maps known IDs to labels, but it occurs after the file reads on lines 14, 18, 22, and 26, so it does not protect the flagged sink.
5. Step 4: The sink is `file_get_contents()` on line 26. The data is used as part of a server-side filename. However, for the reported CWE-918 SSRF class, the constructed string has a fixed relative-path prefix `./` before attacker input and a fixed suffix `/source/impossible.php`, so the visible sink is not a direct attacker-controlled URL fetch.
6. Step 5: No framework protection is visible at the sink. `dvwaPageStartup(array('authenticated'))` on line 6 may enforce authentication, but its implementation was unavailable. PHP itself does not sanitize interpolated filenames passed to `file_get_contents()`.
7. Step 6: The visible code suggests the route is intended for authenticated users because `dvwaPageStartup(array('authenticated'))` is called on line 6. The exact enforcement behavior is not visible.
8. Step 7: A concrete SSRF impact is not supported by the visible code because the attacker cannot place a URL scheme at the start of the `file_get_contents()` argument due to the literal `./` prefix on line 26. A local-path concern is theoretically possible, but the fixed suffix `/source/impossible.php` and absence of visible downstream output make a concrete arbitrary file disclosure path unproven in the provided evidence.
9. Step 8: The weakest point is the lack of pre-sink validation of `$id`; however, the key visible constraint is that the sink argument is not an attacker-controlled URL but a fixed relative path pattern `./<id>/source/impossible.php`, which undermines the reported SSRF consequence.
