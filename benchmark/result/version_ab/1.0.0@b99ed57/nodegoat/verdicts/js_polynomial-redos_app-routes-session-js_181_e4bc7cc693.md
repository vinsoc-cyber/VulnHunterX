# js/polynomial-redos @ app/routes/session.js:181

**Verdict:** FP · **Confidence:** Low (0.35) · **Truth:** real · **Grade:** MISS · **Iterations:** 6

## Reasoning

Although the flagged regex sink and request-body-derived data flow are visible, the supplied follow-up context repeatedly failed to establish any caller or route that makes `handleSignup` attacker-reachable. Because the final decision must be based on a concrete attacker-reachable consequence at the flagged sink rather than merely the absence of a sanitizer, the balance of evidence leans False Positive with low confidence.

## Answers

1. Step 0 / flagged line location: The flagged line is present at app/routes/session.js:181 and its exact text is `if (!EMAIL_RE.test(email)) {`. It lives inside the nested `validateSignup` helper defined at app/routes/session.js:138 within `SessionHandler`. The reported construct is present: `EMAIL_RE.test(email)` applies the regex defined at app/routes/session.js:143.
2. Step 1: The potentially dangerous data originates from HTTP request body input in the visible code: `req.body` is destructured in `handleSignup` at app/routes/session.js:191-198, and `email` is bound at line 192. However, all requested caller/route contexts reported no callers or not found, so an externally reachable HTTP route was not demonstrated.
3. Step 2: Data flow: `req.body` at app/routes/session.js:191-198 → destructured `email` at line 192 → copied into `errors.email` at line 203 → passed to `validateSignup(userName, firstName, lastName, password, verify, email, errors)` at line 206 → received as parameter `email` at line 138 → checked only for non-empty at line 180 → used in `EMAIL_RE.test(email)` at line 181.
4. Step 3: No email length bound, sanitization, regex timeout, or safe-regex replacement is visible before line 181. The only visible check is `if (email !== "")` at app/routes/session.js:180, which does not mitigate ReDoS. The regex itself is defined at line 143 as `const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;`.
5. Step 4: The sink is app/routes/session.js:181: `if (!EMAIL_RE.test(email)) {`. The operation of concern is matching attacker-influenced `email` against `/^[\S]+@[\S]+\.[\S]+$/`, which has multiple unbounded quantifiers over broad character classes and is the pattern CodeQL reports as polynomial-time.
6. Step 5: No automatic framework/library protection is visible. Requested context for Express app initialization, signup route registration, router setup, module exports, body parser, and request body size limits was not found. Therefore, neither a protection nor a reachable route is established by the additional context.
7. Step 6: Required privilege/authentication state is not proven. `handleSignup` at app/routes/session.js:189 appears to be a signup handler and has no visible authentication check, but `all_callers:handleSignup` found no callers and no route registration was available, so attacker reachability remains unconfirmed.
8. Step 7: The theoretical impact, if reachable with a sufficiently large controlled `email`, would be denial of service through CPU consumption in the Node.js event loop during regex evaluation at line 181. However, a concrete attacker-reachable consequence is not established because no route/caller was found.
9. Step 8: The visible weak point is the lack of a length bound before the regex test. But under the final instruction to decide by concrete consequence at the flagged sink, the decisive gap is reachability: the provided and requested context never establishes that an attacker can invoke `handleSignup`.
