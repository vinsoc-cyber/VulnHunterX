/**
 * @name Server-side request forgery via tainted URL
 * @description Tainted user input flows into the URL argument of an
 *              outgoing HTTP request (`http.Get`, `http.Post`, a
 *              `http.Client.Do`, or `http.NewRequest`) without an
 *              allow-list check on host / scheme. This lets the
 *              attacker pivot to internal services
 *              (127.0.0.1, link-local 169.254.169.254 metadata
 *              service, internal VPC ranges).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision medium
 * @id go/ssrf
 * @tags external/cwe/cwe-918
 *       security
 */

import go
import semmle.go.security.FlowSources
import semmle.go.dataflow.TaintTracking
import SsrfFlow::PathGraph

/** URL argument of an outgoing HTTP request. */
class HttpRequestUrlSink extends DataFlow::Node {
  HttpRequestUrlSink() {
    // http.Get(url), http.Post(url, ...), http.Head(url), http.PostForm(url, ...)
    exists(DataFlow::CallNode c |
      c.getTarget().hasQualifiedName("net/http",
        ["Get", "Post", "Head", "PostForm"]) and
      this = c.getArgument(0)
    )
    or
    // http.NewRequest(method, url, body) / http.NewRequestWithContext(ctx, method, url, body)
    exists(DataFlow::CallNode c |
      c.getTarget().hasQualifiedName("net/http", "NewRequest") and
      this = c.getArgument(1)
    )
    or
    exists(DataFlow::CallNode c |
      c.getTarget().hasQualifiedName("net/http", "NewRequestWithContext") and
      this = c.getArgument(2)
    )
    or
    // (*http.Client).Get(url) / .Post(url, ...) / .Head(url) / .PostForm(url, ...)
    exists(DataFlow::MethodCallNode m |
      m.getTarget().hasQualifiedName("net/http", "Client",
        ["Get", "Post", "Head", "PostForm"]) and
      this = m.getArgument(0)
    )
  }
}

module SsrfCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof UntrustedFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof HttpRequestUrlSink }
}

module SsrfFlow = TaintTracking::Global<SsrfCfg>;

from SsrfFlow::PathNode source, SsrfFlow::PathNode sink
where SsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Outgoing HTTP request URL derived from $@ — validate host/scheme " +
  "against an allow-list to prevent SSRF.",
  source.getNode(), "remote source"
