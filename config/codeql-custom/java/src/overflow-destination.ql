/**
 * @name System.arraycopy length not bounded by destination capacity
 * @description `System.arraycopy(src, srcPos, dst, dstPos, length)`
 *              throws ArrayIndexOutOfBoundsException if any computed
 *              index is out of bounds. When `length` is taken from a
 *              tainted protocol field and `dst.length` is not checked
 *              first, the exception either leaks into a client response
 *              or — when caught silently — leaves the destination
 *              partially written.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id java/overflow-destination
 * @tags external/cwe/cwe-805
 *       external/cwe/cwe-806
 *       security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import OverflowFlow::PathGraph

class ArrayCopyLengthSink extends Expr {
  ArrayCopyLengthSink() {
    exists(MethodCall m |
      m.getMethod().hasName("arraycopy") and
      m.getMethod().getDeclaringType().hasQualifiedName("java.lang", "System") and
      this = m.getArgument(4)
    )
    or
    exists(MethodCall m |
      m.getMethod().hasName("copyOfRange") and
      m.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      this = m.getArgument(2)
    )
  }
}

module OverflowCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof ArrayCopyLengthSink }
}

module OverflowFlow = TaintTracking::Global<OverflowCfg>;

from OverflowFlow::PathNode source, OverflowFlow::PathNode sink
where OverflowFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "arraycopy length taken from $@ without explicit dst.length check.",
  source.getNode(), "remote source"
