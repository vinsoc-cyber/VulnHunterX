# js/code-injection @ app/routes/contributions.js:33

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context does not reveal any upstream sanitizer or framework protection, and the flagged line directly executes `req.body.afterTax` with `eval` before validation. Although the exact route/authentication state is not visible, the provided handler contains a clear exploitable code-injection sink for any request path that reaches it.

## Data flow

user-controlled HTTP request body `req.body.afterTax` (`app/routes/contributions.js:33`) → no visible pre-sink validation/sanitization → direct code execution sink `eval(req.body.afterTax)` (`app/routes/contributions.js:33`) → result assigned to `afterTax` (`app/routes/contributions.js:33`) → post-eval validation (`app/routes/contributions.js:47-49`) → post-eval total check (`app/routes/contributions.js:57`) → DAO update (`app/routes/contributions.js:65`)

## Answers

1. Step 0 / flagged line location: The flagged line is present in `app/routes/contributions.js` line 33, inside `ContributionsHandler`, specifically in the method assigned as `this.handleContributionsUpdate` starting at line 28. Exact text: `const afterTax = eval(req.body.afterTax);`. The CodeQL rule’s construct is present on that line: user-derived data is passed to `eval(...)`.
2. Step 1 / source: The dangerous data originates from the HTTP request body, specifically `req.body.afterTax` at `app/routes/contributions.js:33`. This is user-provided request data in an Express-style handler. The additional caller context did not reveal any upstream source transformation or validation.
3. Step 2 / trace: `req.body.afterTax` is read directly at `app/routes/contributions.js:33`; it is passed directly as the argument to `eval(...)` on the same line; the evaluated result is assigned to local variable `afterTax` on line 33. The resulting `afterTax` value is later checked with `isNaN(afterTax)` and numeric comparisons at line 47, included in the total contribution check at line 57, and passed to `contributionsDAO.update(userId, preTax, afterTax, roth, ...)` at line 65. The additional `function:handleContributionsUpdate` context is identical and adds no sanitization before line 33.
4. Step 3 / validation, sanitization, encoding: No validation, sanitization, or encoding is applied to `req.body.afterTax` before it reaches `eval` at line 33. The validation on lines 47-49 occurs after the code has already been evaluated, so it cannot prevent code injection. The safer `parseInt` code on lines 36-41 is inside a block comment and is not executed.
5. Step 4 / sink: The sink is `eval(req.body.afterTax)` at `app/routes/contributions.js:33`. The unsafe operation is dynamic server-side JavaScript code execution using `eval` on request-controlled data.
6. Step 5 / framework or library protections: No automatic framework or library protection is visible. The provided additional context shows no caller, route middleware, schema validation, sanitizer, sandbox, or body parser configuration that constrains `req.body.afterTax` before line 33. Database/DAO protections would not mitigate this sink because execution already occurs at `eval` before the DAO call.
7. Step 6 / privilege or authentication state: The exact route registration and authentication middleware are not visible. The handler reads `req.session.userId` at lines 42-44, suggesting session context may be used, but there is no visible guard in this function. Therefore, the exact required privilege level is not visible; any attacker who can reach this handler and control `req.body.afterTax` can trigger the sink.
8. Step 7 / concrete impact: If an attacker controls `req.body.afterTax`, they can execute arbitrary JavaScript in the server-side Node.js process via line 33. Concrete impact can include remote code execution, data theft from process-accessible resources, application state modification, or denial of service.
9. Step 8 / weakest link: The weakest link is the direct use of `eval` on untrusted request-body input at line 33 before any validation. No complete defense is visible; the later numeric checks on lines 47-57 are too late to stop code execution.
