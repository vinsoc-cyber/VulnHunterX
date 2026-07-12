# js/code-injection @ app/routes/contributions.js:32

**Verdict:** TP · **Confidence:** High (0.99) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The exact flagged line is visible in `ContributionsHandler` / `handleContributionsUpdate` and contains a direct `eval(req.body.preTax)` call. Because remote user input reaches `eval` with no visible sanitizer or guard before execution, this is a clear server-side JavaScript code-injection vulnerability.

## Data flow

app/routes/contributions.js:32 external HTTP body `req.body.preTax` → no sanitization or validation → app/routes/contributions.js:32 `eval(req.body.preTax)` code-execution sink → result assigned to `preTax` → later numeric validation at lines 47-63 occurs only after code execution

## Answers

1. Step 0 / Flagged line located: line 32 in function `ContributionsHandler`, specifically inside `this.handleContributionsUpdate` defined at line 28. Exact flagged line: `const preTax = eval(req.body.preTax);`. The construct described by the rule is present on that line: user-controlled request body data is passed directly to JavaScript `eval`.
2. Step 1 / Source: The dangerous data originates from external HTTP request body input, specifically `req.body.preTax` on line 32. The prefetched scanner context states that `req.body` is remote/external attacker-controllable input.
3. Step 2 / Trace: `req.body.preTax` is read on line 32 and passed directly as the argument to `eval(...)` on the same line. The evaluated result is assigned to `preTax` on line 32. No intermediate assignment, parser, sanitizer, or validator is visible before the sink.
4. Step 3 / Validation/Sanitization: No validation, sanitization, encoding, or safe parsing is applied before line 32. The checks on lines 47-63 happen after `eval` has already executed, so they cannot prevent code injection. The safer `parseInt` approach on lines 36-41 is commented out and therefore not active.
5. Step 4 / Sink: The sink is `eval(req.body.preTax)` on line 32. The unsafe operation is execution of attacker-controlled JavaScript code by `eval`.
6. Step 5 / Framework/Library protections: No framework or library protection is visible at this point. There is no schema validation middleware, request-body validation, sandboxing, allowlist, or numeric conversion before the `eval` call on line 32.
7. Step 6 / Required privilege/authentication: The function later reads `req.session.userId` on lines 42-44, which suggests a session may be involved, but the authentication requirement is not visible in the provided code. However, the scanner-provided context establishes this is externally reachable through `req.body`, so reachability is not in question.
8. Step 7 / Security impact: If an attacker controls `req.body.preTax`, they can execute arbitrary JavaScript in the server-side Node.js process via line 32. The concrete impact is server-side code execution, potentially leading to data theft, denial of service, privilege escalation within the application, or full compromise depending on process privileges.
9. Step 8 / Weakest link: The weakest link is the direct use of remote request-body data in `eval` on line 32 before any validation. There is no visible defense before the dangerous operation.
