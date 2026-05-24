/**
 * @name Tainted value reaches require() or dynamic import
 * @description `require(s)` or `import(s)` where `s` is attacker-influenced
 *              loads arbitrary code into the running Node process,
 *              equivalent to RCE.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id js/untrusted-module-loading
 * @tags external/cwe/cwe-829
 *       external/cwe/cwe-470
 *       security
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXssQuery as DomXssQ
import DataFlow::PathGraph

/** A sink that performs module loading. */
class ModuleLoadSink extends DataFlow::Node {
  ModuleLoadSink() {
    exists(DataFlow::InvokeNode i |
      this = i.getArgument(0) and
      (i.getCalleeName() = "require" or i.getCalleeName() = "import")
    )
    or
    // ES dynamic import — DynamicImportExpr
    exists(DynamicImportExpr di | this = di.getSource().flow())
  }
}

class ModuleLoadConfig extends TaintTracking::Configuration {
  ModuleLoadConfig() { this = "js/untrusted-module-loading" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof ModuleLoadSink }
}

from ModuleLoadConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Module loaded with name from $@ — attacker can require arbitrary code.",
  source.getNode(), "remote source"
