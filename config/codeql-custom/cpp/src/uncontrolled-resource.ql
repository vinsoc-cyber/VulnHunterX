/**
 * @name Uncontrolled resource consumption from external input
 * @description An allocation or loop bound driven by an external (taint)
 *              source without an intervening upper-bound comparison is a
 *              denial-of-service primitive (CWE-770 / CWE-400). Distinct
 *              from `cpp/uncontrolled-allocation-size` (which targets
 *              size-arithmetic flows); this rule focuses on raw size /
 *              iteration-count usage without ANY bounding check.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/uncontrolled-resource
 * @tags external/cwe/cwe-770
 *       external/cwe/cwe-400
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import UncontrolledResourceFlow::PathGraph

/** An expression that drives unbounded resource allocation or iteration. */
class ResourceSink extends Expr {
  ResourceSink() {
    // Size argument to allocation routines
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["malloc", "calloc", "realloc", "reallocarray",
                                          "aligned_alloc", "alloca", "mmap"]) and
      (fc.getArgument(0) = this or fc.getArgument(1) = this)
    )
    or
    // operator new[](size)
    exists(NewArrayExpr nae | nae.getExtent() = this)
    or
    // Loop iteration count: any loop whose condition compares against this expr
    exists(Loop l, ComparisonOperation cmp |
      cmp = l.getCondition() and cmp.getAnOperand() = this
    )
  }
}

module UncontrolledResourceCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof ResourceSink }

  // An upper-bound comparison anywhere along the flow is treated as a barrier.
  predicate isBarrier(DataFlow::Node n) {
    exists(ComparisonOperation cmp | cmp.getAnOperand() = n.asExpr() |
      cmp instanceof LTExpr or cmp instanceof LEExpr
      or cmp instanceof GTExpr or cmp instanceof GEExpr
    )
  }
}

module UncontrolledResourceFlow = TaintTracking::Global<UncontrolledResourceCfg>;

from UncontrolledResourceFlow::PathNode source, UncontrolledResourceFlow::PathNode sink
where UncontrolledResourceFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Resource consumption driven by $@ without an upper-bound check — possible CWE-770 / CWE-400.",
  source.getNode(), "an external source"
