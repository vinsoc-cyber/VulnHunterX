/**
 * @name SQL constructed via helper concat passed to database/sql.Query/Exec
 * @description Built-in `go/sql-injection` flags taint reaching the
 *              `database/sql` Query/Exec calls directly. Many codebases
 *              wrap construction in a helper (Squirrel, manual builders)
 *              that the built-in detector cannot see through. This rule
 *              detects taint flowing into a `+` concatenation with a
 *              string-literal SELECT/INSERT/UPDATE/DELETE that then
 *              flows into a database/sql query.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id go/sql-injection
 * @tags external/cwe/cwe-89
 *       security
 */

import go
import semmle.go.dataflow.TaintTracking
import SqlFlow::PathGraph

/** A string concatenation whose other operand is an SQL-keyword string literal. */
class SqlConcat extends AddExpr {
  SqlConcat() {
    exists(StringLit l |
      l = this.getAnOperand() and
      l.getValue().regexpMatch("(?is).*(SELECT|INSERT|UPDATE|DELETE|UNION|FROM|WHERE).*")
    )
  }
}

class DatabaseQuerySink extends DataFlow::Node {
  DatabaseQuerySink() {
    exists(DataFlow::MethodCallNode m |
      m.getTarget().hasQualifiedName("database/sql", _,
        ["Query", "QueryRow", "QueryContext", "QueryRowContext",
         "Exec", "ExecContext", "Prepare", "PrepareContext"]) and
      this = m.getArgument(0)
      // also handle the (ctx, query, ...) shape — argument 1
      or
      m.getTarget().hasQualifiedName("database/sql", _,
        ["QueryContext", "QueryRowContext", "ExecContext", "PrepareContext"]) and
      this = m.getArgument(1)
    )
  }
}

module SqlCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof UntrustedFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof DatabaseQuerySink }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(SqlConcat c |
      a.asExpr() = c.getAnOperand() and b.asExpr() = c
    )
  }
}

module SqlFlow = TaintTracking::Global<SqlCfg>;

from SqlFlow::PathNode source, SqlFlow::PathNode sink
where SqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value from $@ concatenated with SQL keywords and passed to " +
  "database/sql — use parameterised query.",
  source.getNode(), "remote source"
