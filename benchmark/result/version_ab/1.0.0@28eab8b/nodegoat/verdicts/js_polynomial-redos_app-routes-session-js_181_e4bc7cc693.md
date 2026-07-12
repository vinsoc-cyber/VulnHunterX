# js/polynomial-redos @ app/routes/session.js:181

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is present and performs a regex test on externally controlled `req.body.email`. No visible length bound, sanitizer, safe-regex wrapper, or upstream framework defense is present in either the original snippet or the additional context, so the reachable signup path is vulnerable to regex-based denial of service.

## Data flow

remote/external `req.body` source in `app/routes/session.js` lines 191-198 → destructured `email` at line 192 → optional copy to `errors.email` at line 203 → passed to `validateSignup(..., email, ...)` at line 206 → received as `email` parameter at line 138 → non-empty check only at line 180 → regex sink `EMAIL_RE.test(email)` at line 181, using `EMAIL_RE` defined at line 143

## Answers

1. Step 0 / flagged line: The flagged line is present in `app/routes/session.js` at line 181, inside the nested `validateSignup` function defined within `SessionHandler`. Exact flagged text: `if (!EMAIL_RE.test(email)) {`. The construct described by the rule is present: a regular expression test is performed on `email` using `EMAIL_RE`.
2. Step 1: The vulnerability class is polynomial-time regular expression denial of service, corresponding to `js/polynomial-redos` / CWE-1333 and CWE-400. The dangerous data originates from external user input: `req.body` in `this.handleSignup`, destructured at lines 191-198, with `email` specifically read at line 192.
3. Step 2: The visible data flow is: `req.body` at lines 191-198 → local variable `email` at line 192 → optionally stored in `errors.email` at line 203 → passed as the sixth argument to `validateSignup(userName, firstName, lastName, password, verify, email, errors)` at line 206 → received as parameter `email` in `validateSignup` at line 138 → checked only for non-empty string at line 180 → used in `EMAIL_RE.test(email)` at line 181.
4. Step 3: No adequate validation, sanitization, encoding, or length bounding is visible before the regex sink. Line 180 only checks `email !== ""`, which does not limit input size or remove regex-adversarial structure. The regex is defined at line 143 as `const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;`; this is the validation regex itself, but it is also the potentially expensive operation.
5. Step 4: The sink is line 181: `EMAIL_RE.test(email)`. The unsafe operation is applying the regex from line 143 to attacker-controlled input. The pattern contains repeated `\S+` groups around literals `@` and `.`, and those literals are also matchable by `\S`, creating ambiguous backtracking behavior on crafted non-matching inputs.
6. Step 5: No framework or library protection is visible. The requested additional context did not reveal route middleware, global body-parser limits, schema validation, request truncation, or a safe-regex engine. The responses for `global:app`, `global:bodyParser`, `callee_bodies:router.post`, and `callee_bodies:app.use` all found no relevant context.
7. Step 6: The code path is externally reachable through `this.handleSignup` at line 189, which reads `req.body` at lines 191-198. No authentication or admin check is visible before this handler, and the provided scanner note states the source is remote/external input.
8. Step 7: The concrete security impact is denial of service. A crafted `email` value can cause excessive CPU consumption during `EMAIL_RE.test(email)` at line 181, potentially blocking the Node.js event loop and degrading availability.
9. Step 8: The weakest link is the unbounded, attacker-controlled `email` value reaching a polynomial-backtracking regex at line 181. The defense chain is incomplete because the only visible guard is a non-empty check at line 180, and the additional requested context did not reveal any upstream request-size, schema, or middleware defense.
