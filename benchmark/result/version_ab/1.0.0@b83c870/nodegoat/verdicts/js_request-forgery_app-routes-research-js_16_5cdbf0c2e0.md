# js/request-forgery @ app/routes/research.js:16

**Verdict:** TP · **Confidence:** Low (0.6) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

The flagged sink has a concrete security consequence: a server-side HTTP request is made to a URL built from `req.query.url`, and the response body can be reflected to the client. Although route registration and authentication context were not found, the code is clearly structured as an HTTP handler using `req.query` and `res`, and there is no visible defense preventing SSRF on the flagged path.

## Answers

1. Step 0: The flagged line is present at app/routes/research.js:16 and reads exactly: `return needle.get(url, (error, newResponse, body) => {`. It is inside `ResearchHandler(db)`, in the handler assigned at app/routes/research.js:12: `this.displayResearch = (req, res) => {`. The rule-described construct is present: `needle.get` performs an outbound request using `url` as the request URL.
2. Step 1: The dangerous data originates from HTTP query parameters at app/routes/research.js:15: `req.query.url` and `req.query.symbol`. These are request-derived values; if this handler is invoked for an HTTP request, they are user-controlled.
3. Step 2: Data flow: app/routes/research.js:14 checks `req.query.symbol`; app/routes/research.js:15 concatenates `req.query.url + req.query.symbol` into `const url`; app/routes/research.js:16 passes `url` to `needle.get(url, ...)`; app/routes/research.js:24-25 writes the returned `body` into the response if present.
4. Step 3: No validation, sanitization, allowlist, hostname/IP restriction, scheme restriction, DNS/private-network filtering, or URL parsing is visible. The only check is app/routes/research.js:14, `if (req.query.symbol)`, which is merely a truthiness check for `symbol` and does not constrain `req.query.url` or the final URL.
5. Step 4: The sink is app/routes/research.js:16: `needle.get(url, ...)`. The unsafe operation is a server-side outbound HTTP request to a URL influenced by request query parameters.
6. Step 5: No framework or library protection is visible. `needle.get` is an HTTP client request call, and the code shows no automatic SSRF protection, allowlisted destinations, blocked localhost/private IP ranges, or disabled redirects. Additional requested context did not reveal any route middleware or upstream protection.
7. Step 6: The exact privilege level/authentication state is not visible. Additional context reported no callers for `displayResearch` or `ResearchHandler`, and no `module.exports`, `exports`, `app`, or `router` globals. However, the function signature `(req, res)` and use of `req.query`/`res` indicate this is intended as an HTTP request handler.
8. Step 7: The concrete security impact, if reachable through HTTP as indicated by the handler shape, is SSRF with possible data disclosure. An attacker controlling `req.query.url` can cause the server to request attacker-chosen destinations, including internal services, localhost-only endpoints, or cloud metadata services; the fetched response body may then be returned to the attacker at app/routes/research.js:24-25.
9. Step 8: The weakest link is the direct construction of a request URL from `req.query.url` at app/routes/research.js:15 and its immediate use in `needle.get` at app/routes/research.js:16. No visible defense interrupts this flow; the only uncertainty is missing route registration/caller context.
