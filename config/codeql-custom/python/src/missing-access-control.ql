/**
 * @name Flask/Django/FastAPI handler missing auth decorator/dependency
 * @description A view function registered to a sensitive-looking path
 *              (e.g. `/admin`, `/users/...`) that has no
 *              `@login_required`, `@permission_required`,
 *              `@user_passes_test`, FastAPI `Depends(get_current_user)`,
 *              Flask-Security `@auth_required`, etc.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id py/missing-access-control
 * @tags external/cwe/cwe-862
 *       security
 */

import python

bindingset[s]
predicate sensitivePath(string s) {
  s.regexpMatch("(?i).*(admin|delete|users|accounts|password|secret|" +
                "internal|debug|metrics|key|token).*")
}

/** A route-registering decorator (Flask @app.route / FastAPI @app.get etc.) */
class RouteDecorator extends Decorator {
  RouteDecorator() {
    exists(string s |
      s = this.getName() and
      s in ["route", "get", "post", "put", "delete", "patch"]
    )
  }

  string getPath() {
    result = this.getACall().getArg(0).(StrConst).getText()
  }
}

bindingset[name]
predicate looksLikeAuthDecorator(string name) {
  name.regexpMatch("(?i).*(login_required|permission_required|" +
                   "user_passes_test|auth_required|requires_auth|" +
                   "verify_token|jwt_required).*")
}

predicate hasAuthDecorator(Function f) {
  exists(Decorator d |
    d.getScope() = f and
    looksLikeAuthDecorator(d.getName())
  )
}

from Function f, RouteDecorator route, string path
where
  route.getScope() = f and
  path = route.getPath() and
  sensitivePath(path) and
  not hasAuthDecorator(f)
select f,
  "Handler '" + f.getName() + "' on sensitive route '" + path +
  "' has no auth decorator (@login_required / @permission_required / etc.)."
