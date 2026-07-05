# js/log-injection @ app/routes/session.js:64

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line 64 logs `userName`, which is taken directly from `req.body` at lines 54-57, and no visible sanitization or CRLF removal occurs before the `console.log` sink. Because this unauthenticated login path can be triggered with an invalid username and embedded newlines can forge log entries, the CWE-117 log injection finding is a real issue.

## Data flow

source `req.body` (lines 53-57) → destructuring assignment to `userName` (lines 54-57) → passed unchanged to `userDAO.validateLogin(userName, password, ...)` (line 58) → error branch `err.noSuchUser` (lines 62-63) → sink `console.log("Error: attempt to login with invalid user: ", userName)` (line 64)

## Answers

1. Step 0 / flagged line location: The flagged line is present at line 64 and its exact text is `console.log("Error: attempt to login with invalid user: ", userName);`. The construct described by the rule is present: a user-provided value, `userName`, is written to a log via `console.log`.
2. Step 1: The potentially dangerous data originates from HTTP request body input, `req.body`, destructured at lines 53-57. Specifically, `userName` comes from `req.body` on lines 54-57, which is user-controlled input from the login request.
3. Step 2: Data flow: `req.body` is accessed in `handleLoginRequest` at line 53; `userName` is destructured from `req.body` at lines 54-57; `userName` is passed to `userDAO.validateLogin(userName, password, ...)` at line 58; if validation returns an error with `err.noSuchUser` at lines 62-63, the same `userName` is passed to `console.log` at line 64.
4. Step 3: No validation, sanitization, or encoding for log safety is applied to `userName` before the log sink at line 64. The comments at lines 66-80 describe possible fixes such as encoding or replacing CRLF characters, but those lines are comments only and are not executed. No visible CRLF stripping, escaping, allowlist validation, or log-safe encoding is applied on the flagged path.
5. Step 4: The sink is `console.log` at line 64. The dangerous operation is writing attacker-controlled `userName` into a log entry. If `userName` contains newline or carriage-return characters, it can forge additional log lines or alter log structure, which is CWE-117 log injection.
6. Step 5: No framework or library automatic protection is visible for this logging operation. `console.log` does not provide context-aware CRLF sanitization for untrusted log data. The call uses a separate argument for `userName` at line 64, but that does not remove embedded CRLF characters from the logged value.
7. Step 6: The attacker appears to need no prior authentication. This is the login request handler at line 53, and the vulnerable branch is triggered when `userDAO.validateLogin` reports `err.noSuchUser` at lines 58 and 63, which an unauthenticated user can plausibly cause by submitting a nonexistent username.
8. Step 7: The concrete security impact is log injection / log forging, not RCE or direct data theft. An attacker controlling `userName` can inject line breaks or crafted content into application logs, potentially misleading monitoring, incident response, audit trails, or downstream log parsers.
9. Step 8: The weakest link is the absence of log-specific sanitization immediately before logging untrusted `userName` at line 64. The defense chain is incomplete because the visible code takes request body input from lines 54-57 and logs it at line 64 without CRLF removal or encoding.
