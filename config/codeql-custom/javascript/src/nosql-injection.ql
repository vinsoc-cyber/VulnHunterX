/**
 * @name NoSQL query built from tainted input
 * @description User-controlled data passed directly into a MongoDB / Mongoose
 *              query (find / findOne / update / deleteOne) allows operator
 *              injection — e.g. `{ "$where": "<js>" }` or `{ "$ne": null }`
 *              — which can bypass authentication, exfiltrate data, or
 *              execute arbitrary JavaScript on the database server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id js/nosql-injection
 * @tags external/cwe/cwe-943
 *       security
 */

import javascript
import DataFlow::PathGraph

/** Method names on collection / Mongoose model objects that take a query filter. */
private predicate mongoQueryMethod(string name) {
  name in [
    "find", "findOne", "findOneAndUpdate", "findOneAndDelete",
    "findOneAndRemove", "findOneAndReplace", "findById", "findByIdAndUpdate",
    "findByIdAndDelete", "findByIdAndRemove", "updateOne", "updateMany",
    "deleteOne", "deleteMany", "replaceOne", "remove", "count",
    "countDocuments", "distinct", "aggregate"
  ]
}

/** A sink: the first argument (query filter) of a Mongo collection / model call. */
class MongoQuerySink extends DataFlow::Node {
  MongoQuerySink() {
    exists(DataFlow::MethodCallNode m |
      mongoQueryMethod(m.getMethodName()) and
      this = m.getArgument(0)
    )
  }
}

class NoSqlInjectionConfig extends TaintTracking::Configuration {
  NoSqlInjectionConfig() { this = "js/nosql-injection" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof MongoQuerySink }
}

from NoSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Value from $@ used as MongoDB query filter — possible NoSQL operator injection.",
  source.getNode(), "remote source"
