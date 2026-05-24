/**
 * @name Express route registered without an authentication middleware
 * @description An Express route handler (`app.METHOD(path, handler)`)
 *              whose middleware chain does NOT pass through any
 *              recognised authentication middleware (`passport.authenticate`,
 *              `requireAuth`, `ensureLoggedIn`, `verifyToken`, etc.)
 *              exposes the endpoint to unauthenticated callers.
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

/** A call like `app.get(path, ...)` / `router.post(path, ...)`. */
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

from ExpressRouteRegistration r, string path
where
  path = r.getArgument(0).getStringValue() and
  not chainHasAuth(r) and
  not looksPublic(r)
select r,
  "Route '" + path + "' registered without a recognised authentication " +
  "middleware in its chain — verify auth is enforced elsewhere or add " +
  "passport / requireAuth / verifyToken."
