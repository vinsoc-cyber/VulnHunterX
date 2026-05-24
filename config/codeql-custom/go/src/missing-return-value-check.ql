/**
 * @name Error return discarded on security-relevant function
 * @description A function returning `error` whose result is assigned to
 *              `_` (or never bound at all) silently swallows failure.
 *              For security-relevant operations (`Verify`, `Close` of
 *              a TX/file, `Authenticate`, `Validate`, `Commit`), an
 *              ignored error can mask a security failure.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id go/missing-return-value-check
 * @tags external/cwe/cwe-252
 *       security
 */

import go

bindingset[name]
predicate isSecurityRelevant(string name) {
  name.regexpMatch(
    "(?i).*(verify|validate|authenticate|authorize|commit|close|" +
    "checksignature|writeresponse|flush|sync).*"
  )
}

from CallExpr call, ExprStmt s, FuncDecl callee
where
  s.getExpr() = call and
  // The result is silently discarded — call is in expression-statement position
  callee = call.getCalleeFunction*() and
  isSecurityRelevant(callee.getName()) and
  // Function returns at least one error
  callee.getType().(SignatureType).getResultType(_).hasQualifiedName(_, "error")
select call,
  "Error return of '" + callee.getName() +
  "' is discarded. For security-relevant operations, propagate or log " +
  "the error rather than letting the failure go unnoticed."
