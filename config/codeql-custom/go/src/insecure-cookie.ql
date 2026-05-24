/**
 * @name http.Cookie struct without HttpOnly or SameSite
 * @description An `http.Cookie` literal that carries session/auth state
 *              must set `HttpOnly: true` (CWE-1004), `SameSite:` to
 *              `http.SameSiteLaxMode` or `http.SameSiteStrictMode`
 *              (CWE-1275), and `Secure: true` (CWE-614) for HTTPS-only
 *              deployments. Go's default SameSite is
 *              `SameSiteDefaultMode` which omits the attribute entirely.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id go/insecure-cookie
 * @tags external/cwe/cwe-1004
 *       external/cwe/cwe-1275
 *       external/cwe/cwe-614
 *       security
 */

import go

class CookieLiteral extends CompositeLit {
  CookieLiteral() {
    this.getType().hasQualifiedName("net/http", "Cookie")
  }

  predicate fieldIsTrue(string name) {
    exists(KeyValueExpr kv |
      kv = this.getAnElement() and
      kv.getKey().(Ident).getName() = name and
      kv.getValue().(BoolLit).getBoolValue() = true
    )
  }

  predicate fieldEquals(string name, string val) {
    exists(KeyValueExpr kv |
      kv = this.getAnElement() and
      kv.getKey().(Ident).getName() = name and
      kv.getValue().toString() = val
    )
  }
}

from CookieLiteral c, string missing
where
  (not c.fieldIsTrue("HttpOnly") and missing = "HttpOnly (CWE-1004)")
  or
  (not (c.fieldEquals("SameSite", "http.SameSiteLaxMode") or
        c.fieldEquals("SameSite", "http.SameSiteStrictMode") or
        c.fieldEquals("SameSite", "SameSiteLaxMode") or
        c.fieldEquals("SameSite", "SameSiteStrictMode"))
     and missing = "SameSite (CWE-1275)")
  or
  (not c.fieldIsTrue("Secure") and missing = "Secure (CWE-614)")
select c,
  "http.Cookie literal without " + missing + "."
