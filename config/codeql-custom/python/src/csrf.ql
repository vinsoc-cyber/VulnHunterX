/**
 * @name Django @csrf_exempt on view accepting POST/PUT/DELETE
 * @description `@csrf_exempt` disables CSRF protection for a view. When
 *              that view also reads `request.POST` / `request.body`,
 *              the application is exposed to CSRF unless authentication
 *              is by other means (token in header, mTLS).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id py/csrf
 * @tags external/cwe/cwe-352
 *       security
 */

import python

/** A function decorated with @csrf_exempt. */
class CsrfExemptView extends Function {
  CsrfExemptView() {
    exists(Decorator d |
      d.getScope() = this and
      d.getName() = "csrf_exempt"
    )
  }
}

predicate readsMutatingRequestData(Function f) {
  exists(Attribute a |
    a.getScope*() = f and
    a.getName() in ["POST", "body", "data", "FILES"] and
    a.getObject().toString() = "request"
  )
}

from CsrfExemptView f
where readsMutatingRequestData(f)
select f,
  "View '" + f.getName() + "' is decorated @csrf_exempt and reads " +
  "request.POST/body/data — CSRF protection bypassed. Verify auth " +
  "is via a header token or remove @csrf_exempt."
