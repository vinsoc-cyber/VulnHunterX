/**
 * @name HTTP request smuggling risk (conflicting length headers handled)
 * @description An `http.Request` handler that reads both
 *              `Content-Length` and `Transfer-Encoding: chunked` from
 *              the request without rejecting the duplicated framing is
 *              exposed to HTTP request smuggling — a layer-7 attack
 *              against intermediaries that interpret one and forward
 *              the other.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision low
 * @id go/input-validation
 * @tags external/cwe/cwe-444
 *       security
 */

import go

/** Reads of `r.Header.Get(name)`. */
class HeaderGet extends DataFlow::MethodCallNode {
  HeaderGet() {
    this.getTarget().hasQualifiedName("net/http", "Header", "Get")
  }
  string getHeader() { result = this.getArgument(0).getStringValue() }
}

from FuncDecl handler, HeaderGet contentLen, HeaderGet transferEnc
where
  contentLen.getRoot() = handler.getEntryNode().getRoot() and
  transferEnc.getRoot() = handler.getEntryNode().getRoot() and
  contentLen.getHeader().toLowerCase() = "content-length" and
  transferEnc.getHeader().toLowerCase() = "transfer-encoding"
select handler,
  "Handler reads both Content-Length and Transfer-Encoding from the " +
  "incoming request — verify duplicated framing is rejected to avoid " +
  "HTTP request smuggling."
