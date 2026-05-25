/**
 * @name Prototype pollution via tainted bracket assignment or deep merge
 * @description Writing `obj[key] = value` where `key` is user-controlled
 *              can set `__proto__` / `constructor` / `prototype` and
 *              poison `Object.prototype`. Recursive merge / extend
 *              utilities called with tainted source objects have the
 *              same effect. Use a key allow-list, hasOwnProperty guard,
 *              `Map`, or `Object.create(null)`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision medium
 * @id js/prototype-pollution
 * @tags external/cwe/cwe-1321
 *       security
 */

import javascript
import DataFlow::PathGraph

/** A sink: the property-key expression of a bracketed write `obj[KEY] = ...`. */
class BracketKeySink extends DataFlow::Node {
  BracketKeySink() {
    exists(IndexExpr ix |
      ix = any(AssignExpr a).getLhs() and
      this.asExpr() = ix.getPropertyNameExpr()
    )
  }
}

/** A sink: the source object of a deep merge / extend / set / setWith call. */
class MergeSink extends DataFlow::Node {
  MergeSink() {
    exists(DataFlow::InvokeNode i, string n |
      n in [
        "merge", "mergeWith", "defaultsDeep", "set", "setWith",
        "extend", "assign", "_merge", "deepMerge", "deepExtend"
      ] and
      i.getCalleeName() = n and
      // any argument may carry tainted nested keys
      this = i.getAnArgument()
    )
    or
    exists(DataFlow::MethodCallNode m, string n |
      n in [
        "merge", "mergeWith", "defaultsDeep", "set", "setWith",
        "extend", "assign", "deepMerge", "deepExtend"
      ] and
      m.getMethodName() = n and
      m.getReceiver().asExpr().toString() in ["_", "lodash", "$", "jQuery"] and
      this = m.getAnArgument()
    )
  }
}

class PrototypePollutionConfig extends TaintTracking::Configuration {
  PrototypePollutionConfig() { this = "js/prototype-pollution" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) {
    n instanceof BracketKeySink or n instanceof MergeSink
  }
}

from PrototypePollutionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Property key/object from $@ reaches a bracket-write or deep-merge — " +
  "Object.prototype pollution risk.",
  source.getNode(), "remote source"
