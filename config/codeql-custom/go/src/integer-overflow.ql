/**
 * @name Narrowing integer conversion of tainted value
 * @description `int(x)` / `int32(x)` where `x` is a wider or unsigned
 *              integer derived from an external source silently
 *              truncates and may wrap negative. Bounds checks done in
 *              the wider type before this conversion are bypassed.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id go/integer-overflow
 * @tags external/cwe/cwe-190
 *       external/cwe/cwe-681
 *       security
 */

import go
import semmle.go.dataflow.TaintTracking
import IntFlow::PathGraph

class NarrowingConv extends ConversionExpr {
  NarrowingConv() {
    // Target type is narrower / signed where source is wider / unsigned
    this.getType().(IntegerType).getSize() < this.getOperand().getType().(IntegerType).getSize()
    or
    // uint -> int of same size — still risky (negative values appear)
    this.getType() instanceof SignedIntegerType and
    this.getOperand().getType() instanceof UnsignedIntegerType
  }
}

module IntCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof UntrustedFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(NarrowingConv nc | n.asExpr() = nc.getOperand())
  }
}

module IntFlow = TaintTracking::Global<IntCfg>;

from IntFlow::PathNode source, IntFlow::PathNode sink
where IntFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Narrowing integer conversion of tainted value from $@ — upstream " +
  "bounds checks in the wider type are bypassed.",
  source.getNode(), "remote source"
