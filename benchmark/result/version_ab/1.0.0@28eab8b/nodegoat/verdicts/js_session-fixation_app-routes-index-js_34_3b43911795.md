# js/session-fixation @ app/routes/index.js:34

**Verdict:** TP · **Confidence:** High (0.95) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The shown login handler authenticates the user and then assigns `req.session.userId = user._id` on the existing session without regenerating or invalidating the session ID. Because the unauthenticated `/login` route at line 34 reaches this handler directly, this is a clear CWE-384 session fixation vulnerability.

## Data flow

Unauthenticated HTTP POST /login request (line 34) → Express dispatches to `sessionHandler.handleLoginRequest` (line 34), where `sessionHandler` was instantiated at line 15 → `handleLoginRequest` reads `userName` and `password` from `req.body` → `userDAO.validateLogin(userName, password, callback)` authenticates the credentials → on success, existing `req.session` is upgraded via `req.session.userId = user._id` without `req.session.regenerate` → redirect to authenticated area

## Answers

1. Step 0 / flagged line: The flagged line is present at line 34: `app.post("/login", sessionHandler.handleLoginRequest);`. This is an Express POST route registration for `/login` that invokes the login handler, which is the construct described by the `js/session-fixation` rule.
2. Step 1: The relevant source is an unauthenticated HTTP POST request to `/login` registered at line 34. In the provided `SessionHandler.handleLoginRequest`, the login credentials originate from `req.body` via destructuring of `userName` and `password`; the session being upgraded is the existing `req.session` associated with that request.
3. Step 2: Data/control flow is: `sessionHandler` is created at line 15 with `new SessionHandler(db)` → `/login` POST is registered at line 34 with `sessionHandler.handleLoginRequest` → inside `handleLoginRequest`, `userName` and `password` are read from `req.body` → they are passed to `userDAO.validateLogin(userName, password, callback)` → on successful authentication, the callback receives `user` → the code assigns `req.session.userId = user._id` on the existing session → the user is redirected to `/benefits` or `/dashboard`.
4. Step 3: Credential validation occurs through `userDAO.validateLogin(userName, password, callback)`, but no session invalidation or regeneration is applied in the successful login path. The code comments explicitly describe the fix as wrapping the assignment in `req.session.regenerate(() => {})`, but the actual login code directly executes `req.session.userId = user._id` without regeneration. This is insufficient for CWE-384 session fixation.
5. Step 4: The sink is the successful-login session upgrade in `handleLoginRequest`, specifically `req.session.userId = user._id`. The dangerous operation is binding an authenticated user identity to the pre-existing session ID rather than first regenerating or invalidating the session.
6. Step 5: No automatic framework protection is visible at the flagged route registration on line 34 or in the shown login handler. Express route registration does not itself regenerate sessions. The application knows how to regenerate sessions because `handleSignup` uses `req.session.regenerate(() => { ... })`, but the login path does not use that protection.
7. Step 6: The attacker does not need to be authenticated to reach this path. The `/login` POST route at line 34 is registered without `isLoggedIn` or `isAdmin`, unlike protected routes such as `/dashboard` at line 44 and `/profile` at lines 47-48.
8. Step 7: The concrete security impact is session fixation leading to account/session hijacking. If an attacker can cause a victim to authenticate using a session ID known or fixed by the attacker, the application will attach `user._id` to that same existing session, allowing the attacker to reuse the fixed session as the victim.
9. Step 8: The weakest link is the successful-login path in `handleLoginRequest`: after valid credentials are accepted, it directly sets `req.session.userId = user._id` without calling `req.session.regenerate`. The defense is incomplete because the session identifier is not rotated at the privilege boundary.
