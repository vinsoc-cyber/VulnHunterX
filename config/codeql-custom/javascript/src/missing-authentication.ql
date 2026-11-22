/**
 * @name Express route registered without an authentication middleware
 * @description An Express route handler (`app.METHOD(path, handler)`)
 *              whose middleware chain does NOT pass through any
 *              recognised authentication middleware (`passport.authenticate`,
 *              `requireAuth`, `ensureLoggedIn`, `verifyToken`, etc.)
 *              exposes the endpoint to unauthenticated callers. Client-side
 *              HTTP calls (`axiosInstance.post('/api/x', body)`, `fetch`, etc.)
 *              are NOT route registrations and are excluded.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision low
 * @id js/missing-authentication
 * @tags external/cwe/cwe-306
 *       external/cwe/cwe-862
 *       security
 */

import javascript

/**
 * A call like `app.get(path, handler)` / `router.post(path, handler)`.
 *
 * Crucially this must be a SERVER route registration, NOT a client-side HTTP
 * call. A frontend `axiosInstance.post('/api/x', body)` has the same shape
 * (method name + string first arg) but defines no endpoint and enforces no
 * auth — flagging it as "missing authentication" produced the dominant
 * false-positive cohort on SPA codebases (eoffice-superweb: 53 such alerts,
 * 0 real). We distinguish them by:
 *   - excluding HTTP-client receivers (axios/fetch/http/...); and
 *   - requiring server-route evidence: a function/handler argument, or a
 *     receiver that looks like an Express app/router.
 */
class ExpressRouteRegistration extends DataFlow::MethodCallNode {
  ExpressRouteRegistration() {
    this.getMethodName() in [
      "get", "post", "put", "delete", "patch", "all", "use"
    ] and
    // First argument is a string path
    exists(this.getArgument(0).getStringValue())
  }

  /** All non-path arguments — the middleware/handler chain. */
  DataFlow::Node getAChainEntry() {
    exists(int i | i >= 1 and result = this.getArgument(i))
  }
}

/** Textual receiver, e.g. `axiosInstance` in `axiosInstance.post(...)`. */
string receiverText(DataFlow::MethodCallNode m) {
  result = m.getReceiver().asExpr().toString()
}

/** Some non-path argument is a function literal — the route handler. */
predicate hasHandlerArgument(DataFlow::MethodCallNode m) {
  exists(int i | i >= 1 and m.getArgument(i).asExpr() instanceof Function)
}

/** The call is a client-side HTTP request (axios/fetch/http client). */
predicate isHttpClientCall(DataFlow::MethodCallNode m) {
  receiverText(m)
      .regexpMatch("(?i).*(axios|fetch|https?|\\$http|superagent|\\bgot\\b|" +
                   "\\bky\\b|httpclient|apiclient|restclient|xhr|httprequest).*")
}

/** Receiver looks like an Express app/router (unambiguous names only). */
predicate receiverLooksLikeRouter(DataFlow::MethodCallNode m) {
  receiverText(m)
      .regexpMatch("(?i)(app|server|express|route|router|.*router|.*route)")
}

bindingset[name]
predicate isAuthMiddlewareName(string name) {
  name.toLowerCase().regexpMatch(
    ".*(auth|authenticate|ensureLoggedIn|requireAuth|requireLogin|" +
    "verifyToken|verifyJwt|checkAuth|isAuthenticated|jwtVerify|" +
    "passport).*"
  )
}

/** Heuristic: chain entry references an auth middleware. */
predicate chainHasAuth(ExpressRouteRegistration r) {
  exists(DataFlow::Node entry, string name |
    entry = r.getAChainEntry() and
    (
      name = entry.asExpr().(VarRef).getName()
      or
      name = entry.asExpr().(InvokeExpr).getCalleeName()
      or
      name = entry.asExpr().(PropAccess).getPropertyName()
    ) and
    isAuthMiddlewareName(name)
  )
}

/** Heuristic: detect a public route that genuinely should be unauth. */
predicate looksPublic(ExpressRouteRegistration r) {
  exists(string path |
    path = r.getArgument(0).getStringValue() and
    path.regexpMatch("(?i).*(login|register|signup|signin|public|health|" +
                     "metrics|status|favicon|robots).*")
  )
}

/**
 * Heuristic: the application enforces authentication GLOBALLY, so per-route
 * chains legitimately omit auth middleware. Covers:
 *  - NestJS global guards: an `APP_GUARD` DI provider, or `useGlobalGuards(...)`.
 *  - Express: a top-level `app.use(authMiddleware)` (no path argument) whose
 *    argument name looks like auth.
 * When present, the per-route "missing auth" signal is dominated by false
 * positives (auth is real, just not in the inline chain), so suppress it.
 */
predicate hasGlobalAuthEnforcement() {
  exists(VarRef v | v.getName() = "APP_GUARD")
  or
  exists(PropAccess p | p.getPropertyName() = "APP_GUARD")
  or
  exists(DataFlow::MethodCallNode m | m.getMethodName() = "useGlobalGuards")
  or
  exists(DataFlow::MethodCallNode m |
    m.getMethodName() = "use" and
    not exists(m.getArgument(0).getStringValue()) and
    isAuthMiddlewareName(m.getArgument(0).asExpr().(VarRef).getName())
  )
}

from ExpressRouteRegistration r, string path
where
  path = r.getArgument(0).getStringValue() and
  // Must be a SERVER route registration, not a client HTTP call (axios/fetch).
  not isHttpClientCall(r) and
  (hasHandlerArgument(r) or receiverLooksLikeRouter(r)) and
  not chainHasAuth(r) and
  not looksPublic(r) and
  not hasGlobalAuthEnforcement()
select r,
  "Route '" + path + "' registered without a recognised authentication " +
  "middleware in its chain — verify auth is enforced elsewhere or add " +
  "passport / requireAuth / verifyToken."
