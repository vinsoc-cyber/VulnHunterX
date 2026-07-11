# php.lang.security.phpinfo-use.phpinfo-use @ phpinfo.php:8

**Verdict:** TP · **Confidence:** High (0.88) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is exactly `phpinfo();` at phpinfo.php:8, matching the rule’s sensitive-information-disclosure sink. The only visible gate is apparent authentication at phpinfo.php:6, and no visible redaction, admin-only authorization, or environment restriction prevents disclosure of PHP/server configuration to an authenticated user.

## Data flow

PHP/runtime/server/environment configuration → direct diagnostic output by `phpinfo()` at phpinfo.php:8 → response/output to requester after visible call to `dvwaPageStartup(array('authenticated'))` at phpinfo.php:6; requested additional context for `dvwaPageStartup` and `DVWA_WEB_PAGE_TO_ROOT` was unavailable and adds no visible mitigation

## Answers

1. Step 0 / flagged line location: The flagged line is present at `phpinfo.php:8` and its exact text is `phpinfo();`. This is top-level PHP script code, not inside a named function; the provided function context is `<unknown>`. The construct described by the rule, a direct call to PHP's `phpinfo()` function, is present on the flagged line.
2. Step 1: The potentially dangerous information does not originate from user input. The ultimate source is PHP/runtime/server/environment configuration exposed by `phpinfo()` at `phpinfo.php:8`, such as PHP version, loaded modules, configuration values, filesystem paths, environment details, and other deployment metadata.
3. Step 2: The visible execution/data chain is: `define('DVWA_WEB_PAGE_TO_ROOT', '')` at `phpinfo.php:3` → `require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php'` at `phpinfo.php:4` → `dvwaPageStartup(array('authenticated'))` at `phpinfo.php:6` → direct call to `phpinfo()` at `phpinfo.php:8`. There is no variable assignment or transformation carrying the `phpinfo()` output; the PHP built-in directly emits the information.
4. Step 3: No validation, sanitization, redaction, or encoding of the `phpinfo()` output is visible before line 8. For CWE-200, output encoding would not be an adequate mitigation anyway because the issue is disclosure of sensitive configuration information itself. The additional requested context for `dvwaPageStartup` and `DVWA_WEB_PAGE_TO_ROOT` was unavailable, so it does not add any visible sanitizer or defense.
5. Step 4: The sink is `phpinfo();` at `phpinfo.php:8`. The unsafe operation is invoking PHP's diagnostic function, which emits detailed PHP/server/environment configuration to the response/output stream.
6. Step 5: The only visible protection is `dvwaPageStartup(array('authenticated'))` at `phpinfo.php:6`, which appears to require authentication. Its implementation was requested but unavailable, so no stronger framework/library protection, admin-only authorization, environment gating, or output suppression is visible in the provided context.
7. Step 6: Based on visible code, the attacker likely needs to be an authenticated user because line 6 passes `array('authenticated')` to `dvwaPageStartup`. There is no visible admin-only requirement or other privilege check in the provided code.
8. Step 7: The concrete security impact is sensitive information disclosure. An authenticated attacker who can access this script can obtain detailed PHP and server configuration information useful for follow-on attacks, version-specific exploit selection, path discovery, and environment reconnaissance.
9. Step 8: The weakest link is the direct production-exposed diagnostic call `phpinfo();` at `phpinfo.php:8`. The visible defense chain contains only an apparent authentication gate at line 6 and no visible restriction that prevents authenticated users from viewing sensitive environment details.
