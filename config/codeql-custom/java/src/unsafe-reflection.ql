/**
 * @name Tainted value used in reflective class/method lookup
 * @description `Class.forName(s)` / `ClassLoader.loadClass(s)` /
 *              `Method.invoke` / `Constructor.newInstance` invoked with
 *              an attacker-controlled name allows loading of arbitrary
 *              classes — potentially gadget classes whose static
 *              initialisers or constructors perform privileged actions.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/unsafe-reflection
 * @tags external/cwe/cwe-470
 *       security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import RefFlow::PathGraph

class ReflectiveLookupSink extends Expr {
  ReflectiveLookupSink() {
    exists(MethodCall m |
      this = m.getArgument(0) and
      (
        (m.getMethod().hasName("forName") and
         m.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class"))
        or
        (m.getMethod().hasName(["loadClass", "findClass"]) and
         m.getMethod().getDeclaringType().getASupertype*()
            .hasQualifiedName("java.lang", "ClassLoader"))
        or
        (m.getMethod().hasName(["getMethod", "getDeclaredMethod"]) and
         m.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class"))
      )
    )
  }
}

module RefCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof ReflectiveLookupSink }
}

module RefFlow = TaintTracking::Global<RefCfg>;

from RefFlow::PathNode source, RefFlow::PathNode sink
where RefFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Reflective lookup with name from $@ — attacker may load arbitrary " +
  "classes or methods, enabling RCE via gadget chains.",
  source.getNode(), "remote source"
