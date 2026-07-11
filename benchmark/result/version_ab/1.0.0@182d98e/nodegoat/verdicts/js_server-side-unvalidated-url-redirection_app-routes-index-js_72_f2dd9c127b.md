# js/server-side-unvalidated-url-redirection @ app/routes/index.js:72

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The additional context confirms that the only visible middleware before the sink is an authentication check and does not sanitize or validate the `url` query parameter. Therefore an authenticated user-controlled query parameter flows directly into Express `res.redirect`, creating a clear open redirect.

## Data flow

HTTP request to `GET /learn` (`app/routes/index.js:70`) → `isLoggedInMiddleware` checks only `req.session.userId` and calls `next()` when authenticated (`app/routes/session.js`, provided context) → route handler reads user-controlled `req.query.url` (`app/routes/index.js:72`) → value is passed unchanged to `res.redirect(req.query.url)` (`app/routes/index.js:72`)

## Answers

1. Step 0 / flagged line: In `app/routes/index.js`, inside function `index` at line 11, the exact flagged line 72 is `return res.redirect(req.query.url);`. This matches the CodeQL rule construct: a server-side redirect using a user-provided request value.
2. Step 1: The potentially dangerous data originates from user-controlled HTTP input: the query-string parameter `url`, accessed as `req.query.url` on `app/routes/index.js:72`. The route is registered for `GET /learn` at `app/routes/index.js:70`.
3. Step 2: The data flow is direct. A request reaches the `/learn` route at `app/routes/index.js:70`; Express provides `req` to the route handler; the handler reads `req.query.url` at `app/routes/index.js:72`; that value is passed directly to `res.redirect(...)` at `app/routes/index.js:72`. The additional `isLoggedInMiddleware` context shows only an authentication check before `next()` and does not transform `req.query.url`.
4. Step 3: No redirect-target validation, sanitization, encoding, URL parsing, scheme restriction, hostname allowlist, or same-origin check is visible. The additional `isLoggedInMiddleware` only checks `req.session.userId` and calls `next()` if present; otherwise it redirects to `/login`. It does not validate or modify `req.query.url`.
5. Step 4: The sink is `res.redirect(req.query.url)` at `app/routes/index.js:72`. The unsafe operation is issuing an HTTP redirect to a location controlled by the query string.
6. Step 5: No framework or library protection is visible that would make this safe. Express `res.redirect` redirects to the supplied location; it does not, in the shown code, restrict the destination to a safe host or relative path. The provided middleware does not add such protection.
7. Step 6: The attacker needs an authenticated session, because `/learn` is registered with `isLoggedIn` at `app/routes/index.js:70`, and `isLoggedInMiddleware` allows the request only when `req.session.userId` is present. No admin check is applied to this route.
8. Step 7: The concrete security impact is CWE-601 open redirect. An authenticated attacker can craft a URL such as `/learn?url=https://attacker.example/...` and cause users who follow it to be redirected to an attacker-controlled site, enabling phishing, credential theft, or abuse of trust in the legitimate domain.
9. Step 8: The weakest link is the direct use of `req.query.url` as the redirect destination at `app/routes/index.js:72`. Authentication in `isLoggedInMiddleware` is not a sufficient defense because it only controls access to the route and does not constrain where the redirect may send the user.
