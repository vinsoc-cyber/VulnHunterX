/**
 * @name Server-side request forgery via tainted URL
 * @description An HTTP request constructed from a remote source (req.query,
 *              req.body, req.params, etc.) without strict allow-list
 *              validation lets an attacker pivot to internal services
 *              (cloud metadata, localhost, RFC1918), exfiltrate data,
 *              or scan the internal network.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision medium
 * @id js/ssrf
 * @tags external/cwe/cwe-918
 *       security
 */

import javascript
import DataFlow::PathGraph

/** A sink that performs an outbound HTTP request whose URL/options are tainted. */
class HttpRequestSink extends DataFlow::Node {
  HttpRequestSink() {
    // http.get(url, ...), https.get(url, ...), http.request(url, ...)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() in ["get", "request"] and
      m.getReceiver().asExpr().toString() in ["http", "https"] and
      this = m.getArgument(0)
    )
    or
    // axios.get(url) / axios.post(url, body) / axios(url) / axios({ url })
    exists(DataFlow::MethodCallNode m |
      m.getReceiver().asExpr().toString() = "axios" and
      m.getMethodName() in ["get", "post", "put", "delete", "patch", "request", "head"] and
      this = m.getArgument(0)
    )
    or
    exists(DataFlow::CallNode c |
      c.getCalleeName() = "axios" and
      this = c.getArgument(0)
    )
    or
    // fetch(url, opts)
    exists(DataFlow::CallNode c |
      c.getCalleeName() = "fetch" and
      this = c.getArgument(0)
    )
    or
    // request(url) / request({ url: ... }) / got(url) / needle('get', url)
    exists(DataFlow::CallNode c |
      c.getCalleeName() in ["request", "got", "superagent"] and
      this = c.getArgument(0)
    )
  }
}

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "js/ssrf" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof HttpRequestSink }
}

from SsrfConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "URL from $@ flows into an HTTP request without allow-list validation — " +
  "potential SSRF.",
  source.getNode(), "remote source"
