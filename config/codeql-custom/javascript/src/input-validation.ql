/**
 * @name Express app created without helmet middleware
 * @description An Express application that never calls `app.use(helmet())`
 *              ships without standard security response headers (CSP,
 *              X-Frame-Options, X-Content-Type-Options, Strict-Transport-
 *              Security, etc.). Combined with even minor application
 *              bugs this widens the blast radius significantly.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id js/input-validation
 * @tags external/cwe/cwe-693
 *       security
 */

import javascript

/** A call to express() returning an Express app object. */
class ExpressAppCreation extends DataFlow::CallNode {
  ExpressAppCreation() {
    this.getCalleeName() = "express" and
    this.getNumArgument() = 0
  }
}

/** Does the project anywhere call `app.use(helmet(...))` or just helmet()? */
predicate projectUsesHelmet() {
  exists(DataFlow::InvokeNode i | i.getCalleeName() = "helmet")
  or
  exists(DataFlow::MethodCallNode m |
    m.getMethodName() = "use" and
    m.getArgument(0).asExpr().(InvokeExpr).getCalleeName() = "helmet"
  )
}

from ExpressAppCreation app
where not projectUsesHelmet()
select app,
  "Express app created but helmet() middleware is not used anywhere in " +
  "the project — security response headers are missing (CSP, HSTS, " +
  "X-Frame-Options, etc.)."
