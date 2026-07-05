# php.lang.security.unlink-use.unlink-use @ vulnerabilities/upload/source/impossible.php:54

**Verdict:** FP · **Confidence:** Low (0.35) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

The rule specifically reports unsafe user-controlled file deletion via `unlink()`, but the provided code context contains no `unlink()` call or deletion sink—only image read/write calls. Because the reported construct is absent from the available flagged context, this cannot be confirmed as the specific CWE-22 unlink vulnerability.

## Answers

1. Q1: The vulnerability class is CWE-22/path traversal or unsafe file deletion via PHP `unlink()` using user-controlled input. The ultimate source of `$uploaded_type`, `$uploaded_tmp`, and `$temp_file` is not visible in the provided context; no `$_FILES`, `$_POST`, `$_GET`, network, database, or other source is shown.
2. Q2: Visible data flow only: `$uploaded_type` is compared to the literal `'image/jpeg'` on provided line 1; `$uploaded_tmp` is passed to `imagecreatefromjpeg($uploaded_tmp)` and assigned to `$img` on provided line 2; `$img` and `$temp_file` are passed to `imagejpeg($img, $temp_file, 100)` on provided line 3. No flow to `unlink()` is visible.
3. Q3: The only visible validation is `$uploaded_type == 'image/jpeg'` on provided line 1. This is not path validation and would not, by itself, make a later `unlink()` safe. No visible path normalization, `realpath()` containment check, basename restriction, allowlisted directory check, or other CWE-22 defense is shown for `$uploaded_tmp` or `$temp_file`.
4. Q4: The sink for rule `php.lang.security.unlink-use.unlink-use` should be a PHP `unlink(<path>)` call. No `unlink()` call appears in the provided code. The visible operations are `imagecreatefromjpeg()` on provided line 2 and `imagejpeg()` on provided line 3, which are not the reported unsafe deletion sink.
5. Q5: No framework or library automatic protection for file deletion is visible. PHP image functions on provided lines 2-3 do not provide automatic protection for an `unlink()` path sink, but the relevant `unlink()` sink is also not visible.
6. Q6: The privilege level or authentication state required to trigger this code path is not visible. No routing, session, authorization, or caller context is shown.
7. Q7: If attacker-controlled data reached `unlink()`, the impact could be arbitrary file deletion/path traversal within PHP process permissions, potentially causing denial of service or deletion of application/user files. In the provided code, that impact is not demonstrated because no `unlink()` operation is present.
8. Q8: For this specific rule, the decisive issue is that the reported dangerous construct is absent from the visible flagged context. There is no visible defense proving safe unlink usage, but there is also no visible `unlink()` sink at all; under rule-scope discipline, a finding for an absent construct should not be treated as a True Positive.
