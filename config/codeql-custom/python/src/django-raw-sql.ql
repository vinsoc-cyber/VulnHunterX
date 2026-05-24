/**
 * @name Tainted value reaches Django raw SQL / extra(where=...)
 * @description Django ORM normally parameterises queries safely, but
 *              `Model.objects.raw(s)`, `cursor.execute(s)`, `RawSQL(s)`,
 *              and `QuerySet.extra(where=[s])` accept arbitrary SQL.
 *              When `s` includes attacker-controlled values without
 *              using the `params=` argument, classical SQL injection
 *              applies — and Django's built-in coverage misses these
 *              ORM-adjacent sinks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id py/django-raw-sql
 * @tags external/cwe/cwe-89
 *       security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DjangoRawSqlFlow::PathGraph

class DjangoRawSink extends DataFlow::Node {
  DjangoRawSink() {
    // Model.objects.raw(query)
    exists(API::CallNode c |
      c.getFunction().toString().matches("%.objects.raw") and
      this = c.getArg(0)
    )
    or
    // cursor.execute(query) where query is the only / first arg
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "execute" and
      this = c.getArg(0)
    )
    or
    // django.db.models.expressions.RawSQL(query, ...)
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "RawSQL" and
      this = c.getArg(0)
    )
    or
    // .extra(where=[...])
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "extra" and
      this = c.getArgByName("where")
    )
  }
}

module DjangoRawSqlCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof DjangoRawSink }
}

module DjangoRawSqlFlow = TaintTracking::Global<DjangoRawSqlCfg>;

from DjangoRawSqlFlow::PathNode source, DjangoRawSqlFlow::PathNode sink
where DjangoRawSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value from $@ reaches Django raw-SQL sink — use params= " +
  "argument or a parameterised query.",
  source.getNode(), "remote source"
