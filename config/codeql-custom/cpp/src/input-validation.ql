/**
 * @name Tainted array index without bounds check
 * @description An externally controlled integer used as an array subscript
 *              without a preceding upper-bound comparison against the
 *              array's size. Causes out-of-bounds reads / writes.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @id cpp/input-validation
 * @tags external/cwe/cwe-129
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import IndexFlow::PathGraph

/** An array-subscript expression's offset position. */
class ArraySubscriptIndex extends Expr {
  ArraySubscriptIndex() { exists(ArrayExpr ae | ae.getArrayOffset() = this) }
}

/**
 * A guarded index — flagged false-positive avoidance:
 * the index access appears inside an `if (idx < N) { ... }` block.
 */
predicate inUpperBoundGuard(Expr indexUse) {
  exists(IfStmt ifs, RelationalOperation cmp |
    ifs.getCondition() = cmp and
    cmp.getLessOperand().(VariableAccess).getTarget() =
      indexUse.(VariableAccess).getTarget() and
    indexUse.getEnclosingStmt().getParentStmt*() = ifs.getThen()
  )
}

module IndexCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) {
    n.asExpr() instanceof ArraySubscriptIndex and
    not inUpperBoundGuard(n.asExpr())
  }
}

module IndexFlow = TaintTracking::Global<IndexCfg>;

from IndexFlow::PathNode source, IndexFlow::PathNode sink
where IndexFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Array index taken from $@ without an explicit bounds check before " +
  "the subscript.",
  source.getNode(), "an external source"
