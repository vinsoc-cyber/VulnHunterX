# js/log-injection @ app/routes/session.js:64

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 64 logs `userName` derived directly from `req.body` without any visible sanitization or CRLF neutralization. The login handler is reachable by unauthenticated users, and attacker-controlled newlines or control characters can forge or corrupt log entries.

## Data flow

HTTP request body `req.body` (lines 53-57) → destructuring assignment to `userName` (lines 54-57) → passed to `userDAO.validateLogin(userName, password, ...)` (line 58) → error branch `err.noSuchUser` (line 63) → unsanitized log sink `console.log(..., userName)` (line 64)

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 64 and reads exactly: `console.log("Error: attempt to login with invalid user: ", userName);`. The construct described by the rule is present: a log operation includes `userName`, which is derived from user-provided input.
2. Step 1: The dangerous data originates from HTTP request body input: `req.body` is destructured in lines 53-57. Specifically, `userName` is extracted from `req.body` at lines 54-57, so the ultimate source is unauthenticated user-controlled network/HTTP input.
3. Step 2: Data flow trace: `req.body` is read in `handleLoginRequest` at line 53 and destructured at lines 54-57 into `userName` and `password`; `userName` is passed to `userDAO.validateLogin(userName, password, ...)` at line 58; if `err.noSuchUser` is true at line 63, the same `userName` is passed as the second argument to `console.log` at line 64.
4. Step 3: No validation, sanitization, or encoding is applied to `userName` before the log sink at line 64. Lines 66-80 contain comments describing possible fixes such as CRLF replacement or encoding, but these are commented out and not executed. No visible CRLF stripping, allowlist validation, escaping, or encoding protects the logged value.
5. Step 4: The sink is `console.log("Error: attempt to login with invalid user: ", userName);` at line 64. The dangerous operation is writing attacker-controlled input into logs without neutralizing line breaks or other control characters, which can allow log forging/log injection.
6. Step 5: No framework or library protection is visible at this sink. `console.log` does not provide application-level log integrity protection or CRLF neutralization for attacker-controlled strings. There is no visible logging framework configuration, encoder, sanitizer, or structured logging mechanism that would prevent forged log lines.
7. Step 6: The attacker appears to need no authentication. This code is in `handleLoginRequest` at line 53, processes login form input from `req.body` at lines 54-57, and the vulnerable path is triggered when the submitted username does not exist, via `err.noSuchUser` at line 63.
8. Step 7: The concrete impact is log injection / log forging, affecting audit-log integrity. An attacker controlling `userName` could include newline characters or crafted text to create misleading log entries, obscure attack traces, or interfere with downstream log processing. This is not shown to cause RCE or direct data theft in the provided context.
9. Step 8: The weakest link is the direct logging of raw `userName` at line 64 with no active sanitization. The code even contains commented-out CRLF replacement guidance at lines 66-80, but because it is not executed, there is no complete defense visible.
