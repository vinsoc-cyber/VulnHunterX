/**
 * @name Tainted allocation size
 * @description An allocation whose size is derived (directly or via
 *              arithmetic) from an external source can cause heap
 *              exhaustion, integer-overflow-into-truncation bugs, or
 *              size-zero allocations leading to undefined behaviour.
 *              Built-in `cpp/uncontrolled-allocation-size` misses helper-
 *              wrapped allocators; this rule also tracks taint through
 *              wrapper functions and size multiplications.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/uncontrolled-allocation-size
 * @tags external/cwe/cwe-789
 *       external/cwe/cwe-190
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import TaintFlow::PathGraph

/** Size argument of an allocation routine. */
class AllocationSizeArg extends Expr {
  AllocationSizeArg() {
    exists(FunctionCall fc, int i |
      fc.getArgument(i) = this and
      (
        fc.getTarget().hasGlobalOrStdName(["malloc", "alloca"]) and i = 0
        or
        fc.getTarget().hasGlobalOrStdName(["calloc", "realloc", "reallocarray"]) and
        (i = 0 or i = 1)
        or
        fc.getTarget().hasGlobalOrStdName("aligned_alloc") and i = 1
      )
    )
    or
    // operator new[](size)
    exists(NewArrayExpr nae | nae.getExtent() = this)
  }
}

module TaintCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof AllocationSizeArg }

  // Treat integer multiplications as taint-propagating so n*sizeof(T) flows.
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(MulExpr mul |
      mul.getAnOperand() = a.asExpr() and mul = b.asExpr()
    )
    or
    exists(AddExpr add |
      add.getAnOperand() = a.asExpr() and add = b.asExpr()
    )
  }
}

module TaintFlow = TaintTracking::Global<TaintCfg>;

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Allocation size is derived from $@ — possible heap exhaustion or " +
  "integer-overflow truncation.",
  source.getNode(), "an external source"
