/**
 * @name Tainted value flows into Log4j logger (Log4Shell precondition)
 * @description Tainted user input reaches a Log4j 2.x logging call.
 *              On vulnerable Log4j versions (pre-2.17 or with
 *              `formatMsgNoLookups=false`), the logger expands `${jndi:...}`
 *              substitutions in the message string, enabling RCE
 *              (Log4Shell, CVE-2021-44228). Distinct from generic
 *              log-injection — flagged even when the message looks "safe"
 *              because the substitution happens after formatting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id java/log4j-injection
 * @tags external/cwe/cwe-117
 *       external/cwe/cwe-20
 *       security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import Log4jFlow::PathGraph

/** A Log4j 2.x logging method call. */
class Log4jLogCall extends MethodCall {
  Log4jLogCall() {
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("org.apache.logging.log4j", "Logger") and
    this.getMethod().getName().regexpMatch("trace|debug|info|warn|error|fatal|log")
  }

  Expr getMessageArg() { result = this.getArgument(0) or result = this.getArgument(1) }
}

module Log4jCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(Log4jLogCall c | n.asExpr() = c.getMessageArg())
  }
}

module Log4jFlow = TaintTracking::Global<Log4jCfg>;

from Log4jFlow::PathNode source, Log4jFlow::PathNode sink
where Log4jFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User input flows into Log4j logging call. On vulnerable Log4j " +
  "versions (pre-2.17), `${jndi:...}` substitutions in the message " +
  "enable RCE. Source: $@.",
  source.getNode(), "remote source"
