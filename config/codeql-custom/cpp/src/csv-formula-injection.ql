/**
 * @name CSV cell written with tainted leading character
 * @description Writing user input to a CSV/TSV file via `fputs` / `fprintf`
 *              / `fwrite` without escaping leading `=`, `+`, `-`, `@`,
 *              tab, or carriage-return characters enables formula
 *              injection: a victim opening the file in Excel /
 *              LibreOffice / Google Sheets will execute the formula.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id cpp/csv-formula-injection
 * @tags external/cwe/cwe-1236
 *       security
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.dataflow.new.TaintTracking
import CsvFlow::PathGraph

/** Argument to a file-write where the file extension hint is .csv/.tsv. */
class CsvWriteSink extends Expr {
  CsvWriteSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["fputs", "fputws", "fwrite", "fprintf"]) and
      this = fc.getArgument(0)
      or
      fc.getTarget().hasGlobalOrStdName(["fprintf", "snprintf"]) and
      this = fc.getArgument([2 .. fc.getNumberOfArguments() - 1])
    )
  }
}

module CsvCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }
  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof CsvWriteSink }
}

module CsvFlow = TaintTracking::Global<CsvCfg>;

from CsvFlow::PathNode source, CsvFlow::PathNode sink
where CsvFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Value from $@ written to a CSV-style output. If the value begins with " +
  "'=', '+', '-', '@', tab, or CR it triggers formula execution when the " +
  "file is opened in a spreadsheet.",
  source.getNode(), "external source"
