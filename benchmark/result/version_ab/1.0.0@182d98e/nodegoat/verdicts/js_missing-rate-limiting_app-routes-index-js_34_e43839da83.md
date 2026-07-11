# js/missing-rate-limiting @ app/routes/index.js:34

**Verdict:** TP · **Confidence:** Medium (0.74) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line is present and registers `POST /login` directly to `sessionHandler.handleLoginRequest` with no visible rate-limiting middleware. Because this is an unauthenticated login endpoint and Express provides no automatic throttling, the shown route is vulnerable to brute-force or request-flooding attacks unless a non-visible global or handler-level defense exists.

## Data flow

attacker-controlled network traffic / repeated HTTP POST requests to `/login` (line 34) → Express route registration `app.post("/login", ...)` (line 34) → direct dispatch to `sessionHandler.handleLoginRequest` (line 34), with `sessionHandler` instantiated on line 15 → authentication/authorization handling inside `handleLoginRequest` not visible

## Answers

1. Step 1 / source: The flagged line is present at line 34 and its exact text is `app.post("/login", sessionHandler.handleLoginRequest);`. The construct described by the rule is present: an Express POST route for `/login` is registered without any visible rate-limiting middleware. For this rule, the dangerous input is not a single data value but attacker-controlled network traffic: repeated HTTP POST requests to `/login` and likely login credentials submitted to `sessionHandler.handleLoginRequest` at line 34. The internals of `handleLoginRequest` are not visible in the provided context.
2. Step 2 / trace: Network request to POST `/login` reaches the Express route registered on line 34. Express then dispatches directly to `sessionHandler.handleLoginRequest` on line 34. There are no intermediate route-specific middleware functions between the path and handler on line 34. `sessionHandler` is created from `new SessionHandler(db)` on line 15. The body of `SessionHandler.handleLoginRequest` is not visible in the provided context.
3. Step 3 / validation, sanitization, encoding: No rate-limiting, throttling, CAPTCHA, account lockout, request validation, or other anti-bruteforce control is visible on the flagged route at line 34. There is also no authentication guard middleware on the login route, unlike other routes that use `isLoggedIn` on lines 44, 47, 48, 51, 52, 55, 56, 63, 66, 67, 70, and 76. Any validation inside `handleLoginRequest` is not visible.
4. Step 4 / sink: The sink is the Express route registration on line 34: `app.post("/login", sessionHandler.handleLoginRequest);`. The dangerous operation is exposing an authorization/authentication endpoint without visible rate limiting, allowing repeated login attempts or high-volume requests to reach the login handler.
5. Step 5 / framework or library protections: Express does not provide automatic rate limiting for routes by default. No route-specific rate-limiting middleware is visible on line 34, and no app-level rate limiter is visible in the provided context. Therefore, no framework/library protection can be confirmed from the shown code.
6. Step 6 / required privilege: The attacker appears to need no prior authentication. The `/login` POST route at line 34 does not include `isLoggedIn` or `isAdmin`, while protected routes elsewhere explicitly include `isLoggedIn` starting at line 44.
7. Step 7 / concrete impact: The likely impact is CWE-307-style brute-force login attempts and CWE-400/CWE-770-style resource exhaustion against the login handler. If credentials are checked in `handleLoginRequest`, an attacker could repeatedly guess passwords; even without successful guesses, repeated requests could cause denial of service or backend load.
8. Step 8 / weakest link: The weakest link is the absence of visible rate limiting on the unauthenticated POST `/login` route at line 34. No compensating control is shown in the route declaration or surrounding code.
