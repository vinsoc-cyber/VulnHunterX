/**
 * @name Out-of-bounds read driven by external input
 * @description An array or buffer read whose index / length parameter is
 *              tainted by an external source (argv, getenv, read, recv,
 *              scanf) and does not pass through a bounding check before
 *              reaching the array-access / memcpy sink is a CWE-125 candidate.
 *              Conservative: precision is medium and only direct flows
 *              without intervening range comparisons are reported.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/out-of-bounds-read
 * @tags external/cwe/cwe-125
 *       external/cwe/cwe-129
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import OobReadFlow::PathGraph

/** Index or length argument used in a read-style buffer access. */
class OobReadSink extends Expr {
  OobReadSink() {
    // arr[i] — the index expression
    exists(ArrayExpr ae | ae.getArrayOffset() = this)
    or
    // memcpy(dst, src, n) / memmove / strncpy : n is read-length-controlling
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["memcpy", "memmove", "strncpy", "strncat",
                                          "bcopy", "wmemcpy", "wmemmove", "read",
                                          "fread"]) and
      fc.getArgument(2) = this
    )
    or
    // *(p + offset) — additive offset reaching a pointer dereference
    exists(PointerDereferenceExpr pde, AddExpr add |
      pde.getOperand() = add and add.getAnOperand() = this
    )
  }
}

module OobReadCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof OobReadSink }

  // A comparison against any expression is treated as a sanitiser barrier —
  // conservative: any range check on the tainted value is assumed sufficient.
  predicate isBarrier(DataFlow::Node n) {
    exists(ComparisonOperation cmp | cmp.getAnOperand() = n.asExpr())
  }
}

module OobReadFlow = TaintTracking::Global<OobReadCfg>;

from OobReadFlow::PathNode source, OobReadFlow::PathNode sink
where OobReadFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Read uses a value derived from $@ without an intervening bounds check — possible CWE-125.",
  source.getNode(), "an external source"
