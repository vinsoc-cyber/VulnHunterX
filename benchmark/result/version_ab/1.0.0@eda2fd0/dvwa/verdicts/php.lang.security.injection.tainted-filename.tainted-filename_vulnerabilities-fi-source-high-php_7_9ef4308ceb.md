# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** Medium (0.65) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The reported vulnerability class is tainted filename/SSRF, but the available code contains no file, URL, or network sink using `$file`. The flagged code only performs validation and exits on failure, so the specific dangerous construct required for the reported finding is not present in the available context.

## Data flow

source `$_GET['page']` (line 4) → assignment to `$file` (line 4) → validation via `fnmatch("file*", $file)` and comparison to `"include.php"` (line 7) → error and exit on invalid input (lines 9-10) → no visible file/URL/network sink

## Answers

1. Step 1: The potentially dangerous data originates from user-controlled HTTP query input: `$_GET['page']` assigned on line 4.
2. Step 2: The visible data flow is: `$_GET['page']` on line 4 → assigned to `$file` on line 4 → `$file` is checked with `fnmatch("file*", $file)` and compared to `"include.php"` on line 7.
3. Step 3: Validation is applied on line 7. The code allows values matching `file*` or exactly equal to `include.php`; otherwise it prints an error and exits on lines 9-10. This validation is broad and would not necessarily be sufficient if `$file` were later used in a URL-capable file sink, but no such sink is visible.
4. Step 4: No unsafe sink is visible in the provided code. `$file` is not passed to `include`, `require`, `file_get_contents`, `fopen`, cURL, or any other file/URL-fetching operation in the available context.
5. Step 5: No framework or library automatic protections are visible. This is raw PHP using the `$_GET` superglobal on line 4 and `fnmatch` on line 7.
6. Step 6: Based on the visible code, an attacker would need the ability to make an HTTP request containing a `page` query parameter. No authentication or authorization requirement is visible.
7. Step 7: A concrete SSRF impact cannot be established from the provided code because there is no visible file or network sink. If a sink existed later, impact could include SSRF or unintended file access, but that is not shown.
8. Step 8: The weakest visible link is the broad validation on line 7. However, for the reported CWE-918 finding, the missing element is the dangerous sink: the available code validates input but does not use it in any file or network operation.
