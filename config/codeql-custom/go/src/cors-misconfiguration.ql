/**
 * @name CORS Allow-Origin "*" with Allow-Credentials true
 * @description Setting `Access-Control-Allow-Origin: *` together with
 *              `Access-Control-Allow-Credentials: true` on the same
 *              response is forbidden by browsers but, more importantly,
 *              indicates a misconfiguration: either the wildcard or the
 *              credentials flag is wrong. Reflected-origin (echoing
 *              `req.Header.Get("Origin")` to the Allow-Origin) combined
 *              with credentials is a classic auth-bypass vector.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id go/cors-misconfiguration
 * @tags external/cwe/cwe-942
 *       external/cwe/cwe-346
 *       security
 */

import go

/** A call to `w.Header().Set(name, value)` or `Header().Add(...)`. */
class HeaderSetCall extends DataFlow::MethodCallNode {
  HeaderSetCall() {
    this.getTarget().hasQualifiedName("net/http", "Header", ["Set", "Add"])
  }

  string getHeaderName() { result = this.getArgument(0).getStringValue() }
  Expr getValueExpr() { result = this.getArgument(1).asExpr() }
}

from HeaderSetCall origin, HeaderSetCall creds, Function f
where
  origin.getRoot() = f.getEntryNode().getRoot() and
  creds.getRoot() = f.getEntryNode().getRoot() and
  origin.getHeaderName() = "Access-Control-Allow-Origin" and
  origin.getArgument(1).getStringValue() = "*" and
  creds.getHeaderName() = "Access-Control-Allow-Credentials" and
  creds.getArgument(1).getStringValue() = "true"
select origin,
  "Access-Control-Allow-Origin: * combined with $@ — browsers reject " +
  "but this is symptomatic of a CORS misconfiguration. Either drop " +
  "credentials or replace * with a strict origin allowlist.",
  creds, "Access-Control-Allow-Credentials: true"
