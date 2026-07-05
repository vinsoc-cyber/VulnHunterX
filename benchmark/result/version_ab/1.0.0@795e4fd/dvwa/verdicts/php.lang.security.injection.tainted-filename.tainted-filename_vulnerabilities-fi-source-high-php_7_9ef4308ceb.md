# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** Medium (0.74) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present, but it is only a validation conditional and does not perform a filename/URL fetch or other SSRF-capable operation. Based on the available code, the reported tainted-filename/SSRF construct is absent at the flagged line and no exploitable sink is shown.

## Data flow

source: `$_GET['page']` (line 4) → assignment to `$file` (line 4) → validation/check via `fnmatch("file*", $file)` and `$file != "include.php"` (line 7) → reject path exits (lines 8-10) → no visible unsafe file/URL sink

## Answers

1. Step 0 / Q1: The flagged line is present at line 7: `if( !fnmatch( "file*", $file ) && $file != "include.php" ) {`. The construct visible on that line is a conditional validation check using `fnmatch()` and string comparison, not a file/URL access sink. The potentially dangerous data originates from user-controlled HTTP query input `$_GET['page']` on line 4.
2. Q2: Data flow in the available code is: `$_GET['page']` is read on line 4 and assigned to `$file`; `$file` is passed to `fnmatch("file*", $file)` and compared against `"include.php"` on line 7. If the check fails, execution exits on lines 8-10. No later use of `$file` is available.
3. Q3: Validation is applied on line 7: the value is allowed only if it matches the pattern `file*` or equals `include.php`; otherwise the script echoes an error and exits on lines 8-10. This is pattern-based allowlisting, though permissive. However, for the reported SSRF/tainted-filename vulnerability, there is no visible unsafe sink to evaluate against.
4. Q4: No unsafe sink is visible in the available code. Line 7 uses `fnmatch()` only for pattern matching. There is no visible `include`, `require`, `file_get_contents`, `fopen`, cURL call, URL fetch, stream wrapper dereference, or other operation that would make this an SSRF or unsafe filename use.
5. Q5: No framework or automatic library protection is visible. PHP `fnmatch()` on line 7 is not an SSRF protection mechanism; it merely checks a string against a pattern.
6. Q6: Authentication or privilege requirements are not visible. The source is `$_GET['page']` on line 4, so the value is request-controlled if this script is web-accessible, but access control is not shown.
7. Q7: A concrete security impact cannot be demonstrated from the available code. User input is validated and may pass the conditional, but it is not shown being used to access a server-side URL, file, or resource.
8. Q8: For the reported rule, the weakest link would be a later unsafe file/URL sink using `$file`; however, no such sink is present in the provided code. The decisive point is that the flagged line contains validation logic, not the dangerous operation described by the rule.
