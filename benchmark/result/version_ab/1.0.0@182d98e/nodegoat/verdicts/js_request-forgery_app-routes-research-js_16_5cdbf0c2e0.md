# js/request-forgery @ app/routes/research.js:16

**Verdict:** TP · **Confidence:** High (0.9) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged line is an actual outbound HTTP request sink, and the URL passed to it is directly constructed from user-controlled query parameters with no visible validation or SSRF protection. The additional context does not reveal any caller-side or framework-level defense that would prevent attacker-controlled URLs from reaching `needle.get`.

## Data flow

HTTP query parameter `req.query.url` at app/routes/research.js:15 plus `req.query.symbol` at app/routes/research.js:14-15 → concatenated into `const url` at app/routes/research.js:15 → used as outbound request destination in `needle.get(url, ...)` at app/routes/research.js:16 → fetched `body` may be written to the client at app/routes/research.js:24-25

## Answers

1. Step 0 / flagged line location: The flagged line is present in `app/routes/research.js` line 16 and reads exactly: `return needle.get(url, (error, newResponse, body) => {`. It lives inside `ResearchHandler`, specifically inside the `this.displayResearch = (req, res) => { ... }` request handler defined at lines 12-34. The construct described by `js/request-forgery` is present on that line: an outbound request is made using `needle.get` with a URL value derived from request data.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP query parameters. In the visible code, `req.query.symbol` is checked at line 14, and `req.query.url` is read at line 15. The additional context for `function:displayResearch` confirms the same source and does not show any upstream sanitization.
3. Step 2: Data flow with all available context: `req.query.symbol` is read in the branch condition at `app/routes/research.js:14` → `req.query.url` and `req.query.symbol` are concatenated into `const url` at `app/routes/research.js:15` → `url` is passed as the first argument to `needle.get` at `app/routes/research.js:16` → the response `body`, if present, is written back to the HTTP response at `app/routes/research.js:24-25`. The additional `function:displayResearch` context repeats this same flow and adds no additional transformations.
4. Step 3: No validation, sanitization, allowlist, URL parsing, protocol restriction, hostname restriction, IP-range blocking, or encoding is visible before the sink. The condition `if (req.query.symbol)` at line 14 is only a truthiness check and does not constrain `req.query.url`, `req.query.symbol`, or the final `url` at line 15. The additional caller context reports no recorded callers and no global `app`, but it does not reveal any defense.
5. Step 4: The sink is `needle.get(url, ...)` at `app/routes/research.js:16`. The unsafe operation is a server-side outbound HTTP request whose destination URL is controlled by HTTP query parameters. This is the dangerous operation for CWE-918 / SSRF.
6. Step 5: No framework or library protection is visible. `needle.get` is an HTTP client request call and the provided code shows no configuration or wrapper enforcing safe destinations. The additional context did not provide route middleware, authentication middleware, URL validation middleware, or any protective framework configuration.
7. Step 6: The exact authentication or privilege level required is not visible in the provided context. The additional context states that no callers for `displayResearch` or `ResearchHandler` were found and no global `app` was found, so the route registration and middleware chain are not visible. However, the function itself is a request handler accepting `req` and `res`, and if reachable, the vulnerable path is triggered by supplying `req.query.symbol` and `req.query.url`.
8. Step 7: The concrete security impact is SSRF. An attacker who can reach this handler can cause the server to send requests to attacker-controlled URLs, potentially including internal services, localhost-only endpoints, or cloud metadata services. Because the fetched `body` is written to the response at lines 24-25, successful exploitation may also disclose internal response contents to the attacker.
9. Step 8: The weakest link is the direct use of `req.query.url` in the outbound request URL without any visible allowlist or destination validation before `needle.get` at line 16. No complete defense is visible in either the original code or the additional context.
