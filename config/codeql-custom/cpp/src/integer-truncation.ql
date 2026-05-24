/**
 * @name Tainted wider-integer truncated to narrower size/index
 * @description A tainted (externally controlled) integer of wide type
 *              (size_t / uint64_t / long long) cast or implicitly converted
 *              to a narrower type that is then used as an array index,
 *              buffer size, or memory-copy length. Truncation can wrap
 *              attacker input around the smaller type's range, defeating
 *              upstream "is the value too large?" checks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/integer-truncation
 * @tags external/cwe/cwe-197
 *       external/cwe/cwe-190
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import TaintFlow::PathGraph

/** Narrowing conversion: cast or implicit conversion from a wider int to a narrower one. */
class NarrowingConversion extends Cast {
  NarrowingConversion() {
    this.getType().getSize() < this.getExpr().getType().getSize() and
    this.getType().getUnspecifiedType() instanceof IntegralType and
    this.getExpr().getType().getUnspecifiedType() instanceof IntegralType
  }
}

/** A narrowed integer used in a size/index context. */
class SizeIndexSink extends Expr {
  SizeIndexSink() {
    exists(FunctionCall fc, int i |
      fc.getArgument(i) = this and
      (
        fc.getTarget().hasGlobalOrStdName(["malloc", "alloca", "memcpy", "memmove",
                                            "memset", "strncpy", "strncat", "read",
                                            "write", "recv", "send", "snprintf"]) and
        i in [0 .. 2]
      )
    )
    or
    // Array subscript
    exists(ArrayExpr ae | ae.getArrayOffset() = this)
  }
}

module TruncCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof SizeIndexSink }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(NarrowingConversion nc |
      a.asExpr() = nc.getExpr() and b.asExpr() = nc
    )
  }
}

module TaintFlow = TaintTracking::Global<TruncCfg>;

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value reaches a size/index sink via a narrowing integer " +
  "conversion — bounds checks done in the wider type are bypassed.",
  source.getNode(), "external source"
