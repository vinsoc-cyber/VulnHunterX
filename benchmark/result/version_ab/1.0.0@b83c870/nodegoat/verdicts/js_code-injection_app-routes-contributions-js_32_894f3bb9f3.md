# js/code-injection @ app/routes/contributions.js:32

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context does not reveal any upstream sanitizer or guard; it only confirms no static callers were found, which is not a visible defense because the handler may be invoked as a route callback or from outside the analyzed scope. The flagged sink directly evaluates `req.body.preTax` on line 32 before any validation, making this a clear server-side JavaScript code injection issue.

## Data flow

HTTP request body `req.body.preTax` in `handleContributionsUpdate` (app/routes/contributions.js:32) → directly passed without sanitization to `eval(req.body.preTax)` (app/routes/contributions.js:32) → evaluated result assigned to `preTax` (app/routes/contributions.js:32) → post-execution checks `isNaN(preTax)` / `preTax < 0` (app/routes/contributions.js:47) → post-execution sum check (app/routes/contributions.js:57) → persisted via `contributionsDAO.update(userId, preTax, afterTax, roth, ...)` (app/routes/contributions.js:65)

## Answers

1. Step 0 / flagged line: The flagged line is present in `app/routes/contributions.js` line 32 and reads exactly: `const preTax = eval(req.body.preTax);`. It lives in `this.handleContributionsUpdate = (req, res, next) => { ... }`, defined inside `ContributionsHandler`. The CodeQL-described construct is present on that line: `eval(...)` executes `req.body.preTax`.
2. Step 1 / source: The potentially dangerous data originates from `req.body.preTax` on line 32, which is HTTP request body data in an Express-style request handler. The additional caller context found no static callers, but that does not change the source: the value still comes from `req.body` when this handler is invoked.
3. Step 2 / trace: `req.body.preTax` flows directly into `eval(req.body.preTax)` on line 32, and the evaluated result is assigned to `preTax` on the same line. Separately, `req.body.afterTax` and `req.body.roth` are also evaluated on lines 33-34. After execution, `preTax` is used in validation on line 47, in the contribution sum check on line 57, and in `contributionsDAO.update(userId, preTax, afterTax, roth, ...)` on line 65. The relevant CodeQL path is `req.body.preTax` → `eval(req.body.preTax)` on line 32.
4. Step 3 / validation or sanitization: No validation, sanitization, encoding, or safe parsing is applied before line 32. The visible validation on line 47 and the maximum contribution check on line 57 occur only after the `eval` call has already executed. The commented-out safer `parseInt` approach on lines 36-41 is not active code and provides no protection.
5. Step 4 / sink: The sink is `eval(req.body.preTax)` on line 32. The unsafe operation is server-side JavaScript code execution using attacker-controlled request body input.
6. Step 5 / framework/library protections: No framework or library protection is visible at the sink. The additional context did not show any route-level validation, request schema enforcement, middleware, or sanitizer that constrains `req.body.preTax` before line 32. Express request handling and body parsing do not make `eval` safe.
7. Step 6 / privilege/authentication state: The handler reads `req.session.userId` on lines 42-44, suggesting session-associated behavior, but the provided context still does not show route registration or authentication middleware. The additional context says no static callers were found, but the function may be invoked via callbacks or outside the analysis scope. Therefore, the exact required privilege level is not visible; any user who can reach this handler and control the request body can trigger the issue.
8. Step 7 / concrete security impact: If an attacker controls `req.body.preTax`, they can cause arbitrary JavaScript evaluation in the server-side Node.js process through line 32. This can result in server-side code execution/RCE, data theft, modification of application state, or denial of service, depending on process privileges and runtime environment.
9. Step 8 / weakest link: The weakest link is direct use of `eval` on untrusted request body data at line 32 before any active validation or parsing. The defense chain is incomplete because the only visible checks occur after code execution, and the safer parsing code is commented out.
