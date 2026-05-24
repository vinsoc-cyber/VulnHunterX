/**
 * @name Tainted value assigned to DOM event-handler property
 * @description Setting `element.onclick` / `element.setAttribute('onclick', ...)`
 *              (or any `on*` handler attribute) to a tainted string makes
 *              the browser parse it as JavaScript on first event — a
 *              distinct XSS sink from innerHTML.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id js/event-handler-injection
 * @tags external/cwe/cwe-95
 *       external/cwe/cwe-79
 *       security
 */

import javascript
import DataFlow::PathGraph

/** A sink that sets an `on*` event handler property/attribute. */
class EventHandlerSink extends DataFlow::Node {
  EventHandlerSink() {
    // element.onclick = ...
    exists(PropWrite pw |
      pw.getPropertyName().regexpMatch("on[a-z]+") and
      this = pw.getRhs()
    )
    or
    // element.setAttribute('on*', value)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() = "setAttribute" and
      m.getArgument(0).getStringValue().regexpMatch("(?i)on[a-z]+") and
      this = m.getArgument(1)
    )
  }
}

class EventHandlerConfig extends TaintTracking::Configuration {
  EventHandlerConfig() { this = "js/event-handler-injection" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof EventHandlerSink }
}

from EventHandlerConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value from $@ assigned to event-handler — parsed as JS on " +
  "first event.",
  source.getNode(), "remote source"
