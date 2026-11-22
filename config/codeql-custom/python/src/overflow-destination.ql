/**
 * @name struct.pack_into / ctypes.memmove length from external source
 * @description `struct.pack_into(fmt, buffer, offset, *values)` and
 *              `ctypes.memmove(dst, src, count)` accept raw byte counts
 *              that, when sourced from a tainted protocol field without
 *              a bound against destination size, overrun the destination
 *              buffer (raises an exception or — for memmove — corrupts
 *              memory).
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision low
 * @id py/overflow-destination
 * @tags external/cwe/cwe-805
 *       external/cwe/cwe-806
 *       security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import OverflowFlow::PathGraph

class CopyLengthSink extends DataFlow::Node {
  CopyLengthSink() {
    // ctypes.memmove(dst, src, count) — count is arg 2
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "memmove" and
      this = c.getArg(2)
    )
    or
    // struct.pack_into(fmt, buffer, offset, ...) — offset is arg 2
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "pack_into" and
      this = c.getArg(2)
    )
  }
}

module OverflowCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof CopyLengthSink }
}

module OverflowFlow = TaintTracking::Global<OverflowCfg>;

from OverflowFlow::PathNode source, OverflowFlow::PathNode sink
where OverflowFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Memory-copy length/offset from $@ without explicit destination-size bound.",
  source.getNode(), "remote source"
