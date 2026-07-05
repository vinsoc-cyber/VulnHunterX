# php.lang.security.phpinfo-use.phpinfo-use @ phpinfo.php:8

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 4

## Reasoning

The flagged line is a direct `phpinfo()` call at phpinfo.php:8, which is exactly the sensitive-information disclosure pattern reported by the rule. The only visible guard is `dvwaPageStartup(array('authenticated'))` at phpinfo.php:6, and no visible redaction, admin-only restriction, or other complete defense prevents disclosure of phpinfo output.

## Data flow

PHP/server/runtime environment configuration → internally collected and formatted by built-in `phpinfo()` at phpinfo.php:8 → emitted in the HTTP response from the top-level script. Visible execution chain: define root at phpinfo.php:3 → include DVWA page code at phpinfo.php:4 → startup/authentication call at phpinfo.php:6 → direct `phpinfo()` sink at phpinfo.php:8. Additional requested context was unavailable and does not add any visible defense.

## Answers

1. Step 0 / located flagged line: phpinfo.php:8 is exactly `phpinfo();`. The rule-described construct is present on that line: a direct call to PHP's built-in `phpinfo()` function. It is in top-level script scope; the provided function context is `<unknown>`, not a named function/method.
2. Step 1: No user-controlled input source is required for this rule-specific issue. The sensitive data source is PHP/server/runtime/environment configuration, which is internally collected and displayed by `phpinfo()` at phpinfo.php:8.
3. Step 2: Visible trace: phpinfo.php:3 defines `DVWA_WEB_PAGE_TO_ROOT`; phpinfo.php:4 includes `dvwa/includes/dvwaPage.inc.php`; phpinfo.php:6 calls `dvwaPageStartup(array('authenticated'))`; phpinfo.php:8 directly calls `phpinfo()`. The newly supplied additional context for `callee_bodies:dvwaPageStartup` and the top-level routing/access configuration is unavailable, so it does not change the trace.
4. Step 3: No validation, sanitization, redaction, or encoding of the `phpinfo()` output is visible. The call at phpinfo.php:6 appears to be an authentication/startup check, but its body remains unavailable. In any case, no visible code limits or redacts the sensitive environment information emitted by phpinfo.php:8.
5. Step 4: The sink is phpinfo.php:8, `phpinfo();`. The unsafe operation is outputting detailed PHP configuration, server, module, and environment information to the response.
6. Step 5: No automatic framework/library protection against `phpinfo()` disclosure is visible. `dvwaPageStartup(array('authenticated'))` at phpinfo.php:6 may provide access control, but no implementation or admin-only restriction is visible in the provided context.
7. Step 6: The visible code suggests the page is intended for authenticated users because phpinfo.php:6 passes `array('authenticated')` to `dvwaPageStartup`. There is no visible evidence that access is restricted to administrators only, nor is there visible evidence that the page is unreachable.
8. Step 7: The concrete impact is CWE-200 information disclosure. If reached, phpinfo.php:8 may reveal PHP version, loaded extensions, configuration paths, server variables, environment details, and other deployment information useful for follow-on attacks.
9. Step 8: The weakest link is the unconditional direct call to `phpinfo()` at phpinfo.php:8 after only a visible authenticated-startup check at phpinfo.php:6. No visible defense redacts the output, removes the page, or restricts it to a clearly safe administrative/debug-only context.
