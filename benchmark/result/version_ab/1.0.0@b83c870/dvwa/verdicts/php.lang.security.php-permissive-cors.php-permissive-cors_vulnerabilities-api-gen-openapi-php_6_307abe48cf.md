# php.lang.security.php-permissive-cors.php-permissive-cors @ vulnerabilities/api/gen_openapi.php:6

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 5

## Reasoning

The flagged line unconditionally sets `Access-Control-Allow-Origin: *` with no visible origin validation or access-control defense, and the same endpoint emits generated OpenAPI YAML. This is a real permissive CORS configuration weakness for the flagged sink, though confidence is medium because external routing and deployment exposure are not shown.

## Data flow

hardcoded CORS policy string `Access-Control-Allow-Origin: *` (line 6) → PHP `header()` sends wildcard CORS response header (line 6). Response body: `\OpenApi\Generator::scan(['./src'])` scans local source files (line 4) → `$openapi` (line 4) → `$openapi->toYaml()` (line 12) → `echo` emits YAML response (line 12).

## Answers

1. Step 0 / Locate flagged line: The flagged line is line 6: `header("Access-Control-Allow-Origin: *");`. The construct described by the Semgrep rule is present on that exact line: PHP sets the `Access-Control-Allow-Origin` response header to wildcard `*`.
2. Step 1: The potentially dangerous value originates from a hardcoded string literal on line 6: `Access-Control-Allow-Origin: *`. This is not user-controlled data; it is an insecure CORS policy value configured directly in code. The response body originates from `\OpenApi\Generator::scan(['./src'])` on line 4, which scans local source files.
3. Step 2: The CORS policy data flow is direct: hardcoded wildcard CORS header string on line 6 → PHP `header()` call on line 6 → HTTP response header sent to clients. The response body flow is: local source scan `['./src']` on line 4 → assigned to `$openapi` on line 4 → converted to YAML via `$openapi->toYaml()` on line 12 → emitted with `echo` on line 12.
4. Step 3: No validation, sanitization, origin allowlist, conditional environment check, authentication check, or other CORS restriction is visible before the header is sent. Line 6 unconditionally allows all origins with `*`. There is no visible sufficient mitigation for the permissive CORS policy.
5. Step 4: The sink is the PHP `header()` call on line 6. The unsafe operation is sending `Access-Control-Allow-Origin: *`, which allows JavaScript from any origin to read this endpoint’s response under CORS.
6. Step 5: No framework or library automatic protection is visible. PHP’s `header()` sends the supplied header value directly. The OpenAPI generator on line 4 does not provide visible CORS protection for the header set on line 6.
7. Step 6: No authentication or privilege check is visible in the provided code. Based on the visible snippet, the code is a top-level PHP endpoint that sends headers and echoes output directly, so no required privilege level can be identified from the code. There is no visible admin-only or authenticated-only guard.
8. Step 7: The concrete security impact is that any external website can read the generated OpenAPI YAML response emitted on line 12. This may disclose API routes, schemas, parameters, methods, and internal API documentation generated from `./src` on line 4.
9. Step 8: The weakest link is the unconditional wildcard CORS header on line 6. There is no visible origin allowlist, no conditional CORS policy, and no visible access-control guard before emitting the OpenAPI document on line 12.
