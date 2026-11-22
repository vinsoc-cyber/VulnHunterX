/**
 * @name Tainted value reaches importlib.import_module / __import__ / getattr
 * @description Loading a module or attribute whose name is attacker-
 *              controlled lets the attacker pick any importable module —
 *              including ones whose side effects achieve RCE (os.system,
 *              subprocess.Popen, ctypes loaders).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id py/unsafe-reflection
 * @tags external/cwe/cwe-470
 *       security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import ReflFlow::PathGraph

class ReflectiveLoadSink extends DataFlow::Node {
  ReflectiveLoadSink() {
    exists(DataFlow::CallCfgNode c |
      this = c.getArg(0) and
      (
        c.getFunction().(DataFlow::AttrRead).getAttributeName() = "import_module"
        or
        c.getFunction().toString() = "__import__"
      )
    )
    or
    // getattr(obj, tainted_name)
    exists(DataFlow::CallCfgNode c |
      c.getFunction().toString() = "getattr" and
      this = c.getArg(1)
    )
  }
}

module ReflCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof ReflectiveLoadSink }
}

module ReflFlow = TaintTracking::Global<ReflCfg>;

from ReflFlow::PathNode source, ReflFlow::PathNode sink
where ReflFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Module / attribute name from $@ — attacker can load arbitrary code.",
  source.getNode(), "remote source"
