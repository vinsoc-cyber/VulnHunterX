/**
 * @name User input written to CSV/spreadsheet output (formula injection)
 * @description A `RemoteFlowSource` written into a text/CSV file via
 *              `StreamWriter`/`StringWriter`/`TextWriter` or
 *              `File.WriteAllText`/`AppendAllText` without neutralising a
 *              leading `=`, `+`, `-`, or `@` lets an attacker inject a
 *              spreadsheet formula that executes when the file is opened in
 *              Excel/LibreOffice (CWE-1236). Not covered by the built-in C#
 *              suite.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id cs/csv-formula-injection
 * @tags security
 *       external/cwe/cwe-1236
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.security.dataflow.flowsources.Remote
import CsvFlow::PathGraph

/** An argument to a text/CSV write call. */
class CsvWriteSink extends Expr {
  CsvWriteSink() {
    exists(MethodCall mc |
      mc.getTarget()
          .getDeclaringType()
          .hasFullyQualifiedName("System.IO", ["StreamWriter", "StringWriter", "TextWriter"]) and
      mc.getTarget().getName() = ["Write", "WriteLine", "WriteAsync", "WriteLineAsync"] and
      this = mc.getArgument(0)
    )
    or
    exists(MethodCall mc |
      mc.getTarget().getDeclaringType().hasFullyQualifiedName("System.IO", "File") and
      mc.getTarget().getName() =
        ["WriteAllText", "AppendAllText", "WriteAllLines", "AppendAllLines"] and
      this = mc.getAnArgument()
    )
  }
}

module CsvConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof CsvWriteSink }
}

module CsvFlow = TaintTracking::Global<CsvConfig>;

from CsvFlow::PathNode source, CsvFlow::PathNode sink
where CsvFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A $@ is written to CSV/spreadsheet output without neutralising a leading formula character — CSV formula injection.",
  source.getNode(), "remote source"
