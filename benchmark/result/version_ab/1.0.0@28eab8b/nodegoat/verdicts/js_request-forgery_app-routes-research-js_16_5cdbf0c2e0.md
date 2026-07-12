# js/request-forgery @ app/routes/research.js:16

**Verdict:** TP · **Confidence:** High (0.96) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink on line 16 is an outbound HTTP request using `url`, which is built directly from remote query input on line 15. The additional context reveals no caller, middleware, global app/router validation, or library protection that would sanitize or restrict the URL before `needle.get`, so the SSRF/request-forgery path is clearly exploitable.

## Data flow

remote HTTP query parameter `req.query.url` (app/routes/research.js:15) plus `req.query.symbol` (app/routes/research.js:14-15) → concatenated into `const url` (app/routes/research.js:15) → used as outbound request URL in `needle.get(url, ...)` (app/routes/research.js:16) → fetched response body may be written back to client via `res.write(body)` (app/routes/research.js:24-25)

## Answers

1. Step 0 / flagged-line location: The flagged line is present in `app/routes/research.js` line 16, exact text: `return needle.get(url, (error, newResponse, body) => {`. It lives inside `ResearchHandler`, in the `this.displayResearch = (req, res) => { ... }` handler defined at lines 12-34. The rule-described construct is present on that line: an outbound HTTP request is made with `needle.get` using the variable `url` as the request URL.
2. Step 1: The dangerous data originates from remote user-controlled HTTP query parameters. The source identified by CodeQL is `req.query.url` on line 15. `req.query.symbol` is also taken from the request query string and used in the URL construction at lines 14-15.
3. Step 2: The data flow is: `req.query.symbol` is checked for truthiness at line 14; `req.query.url` is concatenated with `req.query.symbol` into `const url` at line 15; `url` is passed as the first argument to `needle.get(url, ...)` at line 16. The additional provided context repeats the same `ResearchHandler` body and does not add any extra transformation or caller-side validation.
4. Step 3: No validation, sanitization, encoding, allowlist, URL parsing, scheme restriction, hostname restriction, DNS/IP filtering, or internal-network blocking is visible. The only visible guard is `if (req.query.symbol)` on line 14, which merely checks that `symbol` is truthy and does not constrain `req.query.url` or ensure the final URL is safe.
5. Step 4: The sink is `needle.get(url, ...)` at line 16. This is unsafe because it causes the server to initiate an outbound request to a URL derived from attacker-controlled query parameters, creating a server-side request forgery sink.
6. Step 5: No automatic protection from a framework or library is visible. The additional requested context for `global:app` and `global:router` was not found, and the supplied `function:ResearchHandler` context shows no middleware or configuration that would validate or constrain `req.query.url`. `needle.get` itself is an HTTP client call and no safe wrapper or SSRF protection is shown.
7. Step 6: The scanner-provided context states that `req.query.url` is an external/remote input and that reachability from outside has already been established. In the visible code, there is no authentication, authorization, or role check before lines 14-16, so no required higher privilege level is visible.
8. Step 7: If an attacker controls `req.query.url`, they can cause the server to make requests to attacker-chosen destinations. Concrete security impact includes SSRF against internal services, localhost-only administrative endpoints, cloud metadata services, and possible internal data exfiltration because the fetched `body` is written into the HTTP response at lines 24-25. It may also enable internal network scanning or denial of service depending on the environment.
9. Step 8: The weakest link is the direct use of attacker-controlled URL input: `req.query.url` is incorporated into `url` at line 15 and immediately passed to `needle.get` at line 16 without any visible validation or allowlist. No complete defense is present in the provided or additional context.
