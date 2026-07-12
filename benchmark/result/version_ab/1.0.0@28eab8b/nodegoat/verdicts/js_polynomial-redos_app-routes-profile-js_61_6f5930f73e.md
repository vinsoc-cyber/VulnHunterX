# js/polynomial-redos @ app/routes/profile.js:61

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is visible at line 61 and directly evaluates attacker-controlled `bankRouting` from `req.body` using the vulnerable nested-quantifier regex defined at line 59. Neither the original snippet nor the additional context shows any adequate input length bound, type validation, sanitizer, regex timeout, or framework protection before the sink, so this is an exploitable ReDoS/DoS issue.

## Data flow

remote HTTP request body `req.body` (lines 42-50; CodeQL source line 50) → destructuring assignment extracts `bankRouting` (line 49) → no visible validation/sanitization/type check/length limit → vulnerable regex assigned to `regexPattern` as `/([0-9]+)+\#/` (line 59) → sink `regexPattern.test(bankRouting)` (line 61). Additional context: no recorded callers for `handleProfileUpdate`, and no `app`, `router`, `bodyParser`, or `express` globals were found; this adds no visible defense.

## Answers

1. Step 0 / flagged line: The flagged line is present in `ProfileHandler`, inside `this.handleProfileUpdate` starting at line 40. The exact flagged line is line 61: `const testComplyWithRequirements = regexPattern.test(bankRouting);`. The construct described by the rule is present on that line: a regular expression is executed with `.test(...)` using `bankRouting` as input.
2. Step 1: The potentially dangerous data originates from remote/external user input in the HTTP request body. In the visible code, `req.body` is destructured at lines 42-50, and `bankRouting` is extracted at line 49. The CodeQL dataflow source also identifies `[SOURCE] line 50: req.body` as external input.
3. Step 2: Data flow is: `req.body` at lines 42-50 → destructuring assignment extracts `bankRouting` at line 49 → `bankRouting` is used directly as the argument to `regexPattern.test(bankRouting)` at line 61. The regex used by this sink is defined at line 59 as `const regexPattern = /([0-9]+)+\#/;`. The additional context did not reveal any caller or global middleware that changes this chain.
4. Step 3: No validation, sanitization, encoding, type check, length limit, or safe normalization of `bankRouting` is visible before line 61. The regex test at line 61 is itself intended as validation, but it is not sufficient for ReDoS because the active pattern at line 59 contains nested quantifiers: `([0-9]+)+`. The comments at lines 52-58 describe this as insecure and mention a safer pattern, but the unsafe pattern remains in use at line 59.
5. Step 4: The sink is line 61: `const testComplyWithRequirements = regexPattern.test(bankRouting);`. The unsafe operation is evaluating the vulnerable regular expression from line 59, `/([0-9]+)+\#/`, against attacker-controlled input. This can cause excessive backtracking on long strings with many repeated digits, such as many `0` characters without the required `#` suffix.
6. Step 5: No framework or library protection is visible. The additional requested context returned no `app`, `router`, `bodyParser`, or `express` globals, and no caller was found for `handleProfileUpdate`. Therefore, no upstream body-size limit, validation middleware, rate limiting, authentication middleware, or regex timeout is visible in the provided context. The absence of recorded callers does not negate the scanner-provided external taint source.
7. Step 6: The exact privilege level is not fully visible. The code later reads `req.session.userId` at lines 78-80, suggesting this handler may be used by a session-authenticated profile update path, but no explicit authentication guard is visible. The scanner context establishes that remote/external `req.body` data reaches the sink, so the sink is externally reachable; the precise required authentication state remains not visible in provided context.
8. Step 7: The concrete security impact is denial of service. An attacker who controls `bankRouting` can supply a long non-matching digit string that forces the regex at lines 59 and 61 into expensive backtracking, consuming CPU and potentially blocking the Node.js event loop.
9. Step 8: The weakest link is the direct application of the unsafe nested-quantifier regex at line 59 to untrusted `bankRouting` input at line 61 without any visible bounding or sanitization. No complete defense is visible in the original code or in the additional context.
