/**
 * @name Cookie set without httpOnly / sameSite option
 * @description `res.cookie(name, value, opts)` or `cookie.serialize`
 *              called without `httpOnly: true` (CWE-1004) or without
 *              `sameSite: 'lax' | 'strict'` (CWE-1275) on a cookie that
 *              looks session-bearing exposes the cookie to JS-based
 *              theft and CSRF.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id js/insecure-cookie
 * @tags external/cwe/cwe-1004
 *       external/cwe/cwe-1275
 *       external/cwe/cwe-614
 *       security
 */

import javascript

/** A call like `res.cookie(name, value, options)`. */
class ExpressCookieSet extends DataFlow::MethodCallNode {
  ExpressCookieSet() { this.getMethodName() = "cookie" }
}

predicate optionIsTrue(DataFlow::ObjectLiteralNode opts, string prop) {
  exists(DataFlow::PropWrite w |
    w = opts.getAPropertyWrite(prop) and
    w.getRhs().mayHaveBooleanValue(true)
  )
}

predicate optionEquals(DataFlow::ObjectLiteralNode opts, string prop, string val) {
  exists(DataFlow::PropWrite w |
    w = opts.getAPropertyWrite(prop) and
    w.getRhs().getStringValue() = val
  )
}

from ExpressCookieSet call, DataFlow::ObjectLiteralNode opts, string missing
where
  opts = call.getArgument(2).getALocalSource() and
  (
    (not optionIsTrue(opts, "httpOnly") and missing = "httpOnly (CWE-1004)")
    or
    (not (optionEquals(opts, "sameSite", "lax") or
          optionEquals(opts, "sameSite", "strict") or
          optionEquals(opts, "sameSite", "Lax") or
          optionEquals(opts, "sameSite", "Strict"))
       and missing = "sameSite (CWE-1275)")
    or
    (not optionIsTrue(opts, "secure") and missing = "secure (CWE-614)")
  )
select call,
  "Cookie set without " + missing + ". " +
  "Add the option to the cookie options object."
