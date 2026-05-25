/**
 * @name Tainted value flows into outbound HTTP request URL
 * @description A `RemoteFlowSource` (HTTP request parameter, header, body,
 *              etc.) reaches a `URL` / `URI` constructor or an outbound
 *              HTTP client call (`HttpURLConnection.openConnection`,
 *              `WebClient.uri`, Apache HttpClient `execute`) without
 *              validation against an allow-list of trusted destinations.
 *              An attacker can pivot the server to fetch internal
 *              resources (cloud metadata, intranet services), enabling
 *              server-side request forgery (CWE-918).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision medium
 * @id java/ssrf
 * @tags external/cwe/cwe-918
 *       security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import SsrfFlow::PathGraph

/** A URL / URI constructor argument. */
class UrlConstructorArg extends Expr {
  UrlConstructorArg() {
    exists(ConstructorCall c |
      c.getConstructedType().hasQualifiedName("java.net", ["URL", "URI"]) and
      this = c.getAnArgument()
    )
  }
}

/** An outbound HTTP client sink. */
class HttpClientSinkArg extends Expr {
  HttpClientSinkArg() {
    // HttpURLConnection-style: URL.openConnection() / openStream()
    exists(MethodCall m |
      m.getMethod().hasName(["openConnection", "openStream"]) and
      m.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("java.net", "URL") and
      this = m.getQualifier()
    )
    or
    // Spring WebClient.get().uri($URI) / .uri(URI, ...) / Spring RestTemplate.*ForObject
    exists(MethodCall m |
      m.getMethod().hasName(["uri", "getForObject", "getForEntity", "postForObject",
                              "postForEntity", "exchange"]) and
      m.getMethod().getDeclaringType().getASupertype*().getQualifiedName()
          .regexpMatch("org\\.springframework\\.web\\.(client|reactive)\\..*") and
      this = m.getArgument(0)
    )
    or
    // Apache HttpClient: client.execute(HttpUriRequest)
    exists(MethodCall m |
      m.getMethod().hasName("execute") and
      m.getMethod().getDeclaringType().getASupertype*().getQualifiedName()
          .regexpMatch("org\\.apache\\.http(components)?\\..*Client.*") and
      this = m.getArgument(0)
    )
    or
    // OkHttp: new Request.Builder().url($X)
    exists(MethodCall m |
      m.getMethod().hasName("url") and
      m.getMethod().getDeclaringType().getQualifiedName()
          .regexpMatch("okhttp3\\..*") and
      this = m.getArgument(0)
    )
  }
}

module SsrfCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    n.asExpr() instanceof UrlConstructorArg
    or
    n.asExpr() instanceof HttpClientSinkArg
  }
}

module SsrfFlow = TaintTracking::Global<SsrfCfg>;

from SsrfFlow::PathNode source, SsrfFlow::PathNode sink
where SsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Outbound HTTP destination derives from a remote source $@ without " +
  "host allow-list validation — potential SSRF.",
  source.getNode(), "remote source"
