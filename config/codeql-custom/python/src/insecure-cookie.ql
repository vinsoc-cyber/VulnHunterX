/**
 * @name Cookie set without httponly / samesite
 * @description `response.set_cookie(...)` called without `httponly=True`
 *              (CWE-1004) or without `samesite='Lax'`/`'Strict'`
 *              (CWE-1275) on a session/auth cookie leaks the cookie
 *              to client JS and broadens CSRF exposure.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id py/insecure-cookie
 * @tags external/cwe/cwe-1004
 *       external/cwe/cwe-1275
 *       external/cwe/cwe-614
 *       security
 */

import python

class SetCookieCall extends Call {
  SetCookieCall() {
    this.getFunc().(Attribute).getName() = "set_cookie"
  }
}

predicate hasKwArgTrue(Call c, string name) {
  exists(Keyword k |
    k = c.getAKeyword() and
    k.getArg() = name and
    k.getValue().(NameConstant).getId() = "True"
  )
}

predicate hasKwArgString(Call c, string name, string val) {
  exists(Keyword k |
    k = c.getAKeyword() and
    k.getArg() = name and
    k.getValue().(StrConst).getText() = val
  )
}

from SetCookieCall call, string missing
where
  (not hasKwArgTrue(call, "httponly") and missing = "httponly (CWE-1004)")
  or
  (not (hasKwArgString(call, "samesite", "Lax") or
        hasKwArgString(call, "samesite", "Strict") or
        hasKwArgString(call, "samesite", "lax") or
        hasKwArgString(call, "samesite", "strict"))
     and missing = "samesite (CWE-1275)")
  or
  (not hasKwArgTrue(call, "secure") and missing = "secure (CWE-614)")
select call,
  "set_cookie call without " + missing + "."
