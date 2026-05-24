/**
 * @name Tainted format-string template reaches str.format
 * @description Python's `str.format()` exposes attribute and item access
 *              (`{0.__class__.__init__.__globals__[os]}`) inside format
 *              specifiers. When the TEMPLATE string is attacker-controlled,
 *              an attacker can walk up to module globals and exfiltrate
 *              secrets or trigger side effects (CVE-2014-1830 class).
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @id py/unsafe-string-formatting
 * @tags external/cwe/cwe-94
 *       external/cwe/cwe-134
 *       security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import FormatTemplateFlow::PathGraph

/** A receiver of `str.format(...)` or `Formatter().format(...)`. */
class FormatTemplateSink extends DataFlow::Node {
  FormatTemplateSink() {
    // value.format(args)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() = "format" and
      this = m.getObject()
    )
    or
    // Formatter().format(template, args) — template is arg 0
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "format" and
      c.getFunction().(DataFlow::AttrRead).getObject()
        .(DataFlow::CallCfgNode).getFunction().(DataFlow::AttrRead)
        .getAttributeName() = "Formatter" and
      this = c.getArg(0)
    )
    or
    // string.Formatter().vformat(template, args, kwargs)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() = "vformat" and
      this = m.getArg(0)
    )
  }
}

module FormatTemplateCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof FormatTemplateSink }
}

module FormatTemplateFlow = TaintTracking::Global<FormatTemplateCfg>;

from FormatTemplateFlow::PathNode source, FormatTemplateFlow::PathNode sink
where FormatTemplateFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted format template from $@ flows into str.format — attacker " +
  "can navigate to module globals via {obj.__class__.__init__.__globals__}.",
  source.getNode(), "remote source"
