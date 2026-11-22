/**
 * @name Tainted value flows into an outbound HTTP request
 * @description A `RemoteFlowSource` (query string, form field, header, route
 *              value, etc.) reaches the URL of an outbound HTTP call
 *              (`WebRequest.Create`, `HttpClient.GetAsync`/`SendAsync`/...,
 *              `new HttpRequestMessage(...)`) without validation against an
 *              allow-list of trusted destinations. An attacker can pivot the
 *              server to reach internal resources (cloud metadata, intranet
 *              services), enabling server-side request forgery (CWE-918).
 *              The built-in C# suite ships no SSRF query, so this fills that
 *              gap.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision medium
 * @id cs/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.security.dataflow.flowsources.Remote
import SsrfFlow::PathGraph

/** The URL argument of an outbound HTTP call. */
class OutboundHttpUrl extends Expr {
  OutboundHttpUrl() {
    // WebRequest.Create(url) / WebRequest.CreateHttp(url)
    exists(MethodCall mc |
      mc.getTarget().getDeclaringType().hasFullyQualifiedName("System.Net", "WebRequest") and
      mc.getTarget().getName() = ["Create", "CreateHttp", "CreateDefault"] and
      this = mc.getArgument(0)
    )
    or
    // HttpClient.GetAsync(url) / PostAsync(url, ...) / GetStringAsync(url) / ...
    exists(MethodCall mc |
      mc.getTarget()
          .getDeclaringType()
          .hasFullyQualifiedName("System.Net.Http", "HttpClient") and
      mc.getTarget().getName() =
        [
          "GetAsync", "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync",
          "PostAsync", "PutAsync", "PatchAsync", "DeleteAsync", "SendAsync"
        ] and
      this = mc.getArgument(0)
    )
    or
    // new HttpRequestMessage(method, url)
    exists(ObjectCreation oc |
      oc.getTarget()
          .getDeclaringType()
          .hasFullyQualifiedName("System.Net.Http", "HttpRequestMessage") and
      this = oc.getAnArgument()
    )
  }
}

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof OutboundHttpUrl }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from SsrfFlow::PathNode source, SsrfFlow::PathNode sink
where SsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Outbound HTTP destination derives from a $@ without host allow-list validation — potential SSRF.",
  source.getNode(), "remote source"
