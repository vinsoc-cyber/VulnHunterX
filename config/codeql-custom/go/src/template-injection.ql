/**
 * @name text/template.Execute called with tainted template string
 * @description `text/template`'s `Execute` interprets `{{}}` actions and
 *              has no HTML escaping. When the TEMPLATE itself (not the
 *              data) is attacker-controlled, the attacker can call any
 *              method exposed on the data type (e.g. `{{.Env}}`,
 *              `{{call .DangerousFn}}`), enabling SSTI-style RCE.
 *              Distinct from `html/template`, which only escapes output.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id go/template-injection
 * @tags external/cwe/cwe-94
 *       external/cwe/cwe-1336
 *       security
 */

import go
import semmle.go.dataflow.TaintTracking
import TmplFlow::PathGraph

/** A call to text/template.New(...).Parse(s) or template.Must(template.New(...).Parse(s)). */
class TextTemplateParseSink extends DataFlow::Node {
  TextTemplateParseSink() {
    exists(DataFlow::MethodCallNode m |
      m.getTarget().hasQualifiedName("text/template", "Template", "Parse") and
      this = m.getArgument(0)
    )
  }
}

module TmplCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof UntrustedFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof TextTemplateParseSink }
}

module TmplFlow = TaintTracking::Global<TmplCfg>;

from TmplFlow::PathNode source, TmplFlow::PathNode sink
where TmplFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value from $@ parsed as a text/template — attacker can " +
  "invoke methods on the data type via {{...}} actions.",
  source.getNode(), "remote source"
