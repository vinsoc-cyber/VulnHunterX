# js/server-side-unvalidated-url-redirection @ app/routes/index.js:72

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

A second pass over the provided code still shows a direct source-to-sink path in the same route handler: `req.query.url` from the HTTP query string flows directly into `res.redirect` on line 72. No additional caller, struct, or global context is needed to establish CWE-601 here because the source, sink, route registration, and absence of redirect-target validation are all visible in the provided snippet.

## Data flow

app/routes/index.js:70 `app.get('/learn', isLoggedIn, (req, res) => { ... })` receives an HTTP request → app/routes/index.js:72 reads user-controlled `req.query.url` → app/routes/index.js:72 passes it directly to `res.redirect(req.query.url)`

## Answers

1. Step 0 / flagged line location: The flagged line is present in `app/routes/index.js` inside function `index`, specifically in the `/learn` route handler declared at line 70. Exact flagged line 72: `return res.redirect(req.query.url);`. The CodeQL-described construct is present on that line: an Express redirect uses a user-provided query parameter.
2. Step 1: The potentially dangerous data originates from HTTP request query-string input: `req.query.url` on line 72. Because the route is `app.get('/learn', ...)` on line 70, the `url` value can be supplied by a client as `/learn?url=...`.
3. Step 2: The data flow is direct with no intermediate assignments visible: request reaches `GET /learn` route in `app/routes/index.js:70`; handler receives `req` and `res` at line 70; user-controlled value is read as `req.query.url` at line 72; it is immediately passed to `res.redirect(...)` at line 72.
4. Step 3: No validation, sanitization, allowlist, same-origin enforcement, URL parsing, or encoding is visible between source and sink. The middleware `isLoggedIn` on line 70 is an authentication/authorization control, not a redirect-target validation control.
5. Step 4: The sink is `res.redirect(req.query.url)` at `app/routes/index.js:72`. The unsafe operation is issuing a server-side HTTP redirect to a target controlled by the request query string.
6. Step 5: No automatic framework protection is visible that would restrict the redirect target to trusted destinations. Express `res.redirect()` is the redirect mechanism itself; the provided code shows no wrapper or configuration limiting it to relative paths or an allowlisted host.
7. Step 6: The attacker must be an authenticated user because the route includes `isLoggedIn` middleware at line 70. The route does not include `isAdmin`, which is defined at line 27 but not used here.
8. Step 7: The concrete impact is an open redirect. An authenticated attacker can craft a URL such as `/learn?url=https://attacker.example/...` that causes the application to redirect users to an attacker-controlled location, enabling phishing or abuse of trust in the legitimate application domain.
9. Step 8: The weakest link is the direct use of `req.query.url` in the redirect sink at line 72 without any visible validation or allowlist. Authentication at line 70 does not prevent an authenticated attacker from abusing the redirect behavior.
