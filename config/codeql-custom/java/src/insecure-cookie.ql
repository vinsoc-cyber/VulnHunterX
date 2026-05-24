/**
 * @name Cookie set without HttpOnly or SameSite attribute
 * @description A cookie that carries session state or authentication
 *              data must set `HttpOnly` (CWE-1004) so JavaScript cannot
 *              read it via `document.cookie`, and `SameSite=Lax`/`Strict`
 *              (CWE-1275) to limit CSRF exposure. Default servlet
 *              behaviour omits both.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id java/insecure-cookie
 * @tags external/cwe/cwe-1004
 *       external/cwe/cwe-1275
 *       external/cwe/cwe-614
 *       security
 */

import java

/** Construction of a Servlet Cookie. */
class ServletCookieConstruction extends ConstructorCall {
  ServletCookieConstruction() {
    this.getConstructedType()
        .hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "Cookie")
  }
}

predicate setsHttpOnly(Variable v) {
  exists(MethodCall m |
    m.getMethod().hasName("setHttpOnly") and
    m.getQualifier().(VarAccess).getVariable() = v and
    m.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  )
}

predicate setsSecure(Variable v) {
  exists(MethodCall m |
    m.getMethod().hasName("setSecure") and
    m.getQualifier().(VarAccess).getVariable() = v and
    m.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  )
}

from ServletCookieConstruction cons, Variable v, string missing
where
  exists(LocalVariableDeclExpr d |
    d.getVariable() = v and d.getInit() = cons
  ) and
  (
    (not setsHttpOnly(v) and missing = "HttpOnly (CWE-1004)")
    or
    (not setsSecure(v) and missing = "Secure (CWE-614)")
  )
select cons,
  "Cookie '" + v.getName() + "' is created without setting " + missing +
  ". Servlet Cookie has no SameSite setter — set the Set-Cookie header " +
  "manually with SameSite=Lax (CWE-1275)."
