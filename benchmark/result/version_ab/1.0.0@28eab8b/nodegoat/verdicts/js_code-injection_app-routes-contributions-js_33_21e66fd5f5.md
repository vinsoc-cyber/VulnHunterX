# js/code-injection @ app/routes/contributions.js:33

**Verdict:** TP · **Confidence:** High (0.99) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible inside `ContributionsHandler.handleContributionsUpdate` and directly executes remote request-body input with `eval`. No pre-execution sanitizer or guard is visible, and the later validation occurs only after the code has already run.

## Data flow

app/routes/contributions.js:33 remote `req.body.afterTax` → app/routes/contributions.js:33 direct call `eval(req.body.afterTax)` → app/routes/contributions.js:33 assignment to `afterTax` → app/routes/contributions.js:47 post-execution numeric checks → app/routes/contributions.js:65 DAO update call

## Answers

1. Flagged line location: app/routes/contributions.js line 33, exact text: `const afterTax = eval(req.body.afterTax);`. It lives in function `ContributionsHandler`, specifically inside the method assigned at line 28: `this.handleContributionsUpdate = (req, res, next) => {`.
2. The construct described by js/code-injection is present on the flagged line: `eval(...)` is called directly with `req.body.afterTax` on line 33.
3. Source: external/remote HTTP request body input, `req.body.afterTax`, on line 33. The provided scanner context states the source is remote/external input.
4. Relevant chain: app/routes/contributions.js:33 `req.body.afterTax` → app/routes/contributions.js:33 `eval(req.body.afterTax)` → app/routes/contributions.js:33 result assigned to `afterTax` → app/routes/contributions.js:47 numeric validation occurs after execution → app/routes/contributions.js:57 arithmetic check → app/routes/contributions.js:65 passed to `contributionsDAO.update(...)`.
5. No pre-sink validation, sanitization, encoding, or parsing is visible before line 33. The commented-out safer alternative using `parseInt(req.body.afterTax)` appears only inside a block comment at lines 36-41 and is not active code.
6. The sink is app/routes/contributions.js:33, `eval(req.body.afterTax)`. The unsafe operation is server-side JavaScript code execution using attacker-controlled request body content.
7. No framework/library protection is visible at the sink. Database protections are irrelevant to this finding because the code execution happens before the DAO call on line 65.
8. Authentication/privilege context is not fully visible. Lines 42-44 read `userId` from `req.session`, suggesting a session context, but no route or auth middleware is shown. However, the provided taint-source note establishes external reachability from `req.body`.
9. Concrete impact: attacker-controlled JavaScript can execute in the Node.js server process via `eval`, which can lead to server-side code execution, data theft, state manipulation, or denial of service.
10. Weakest link: direct use of remote request-body data in `eval` on line 33 before any validation. The checks on line 47 are post-execution and therefore cannot prevent code injection.
