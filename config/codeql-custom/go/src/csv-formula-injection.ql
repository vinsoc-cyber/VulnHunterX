/**
 * @name Tainted value written to CSV/XLSX cell via encoding/csv or excelize
 * @description `csv.Writer.Write(record)` or `excelize.SetCellValue(...)`
 *              with a value that starts with `=`/`+`/`-`/`@` interprets
 *              as a formula when the file is opened in Excel /
 *              LibreOffice / Google Sheets.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id go/csv-formula-injection
 * @tags external/cwe/cwe-1236
 *       security
 */

import go
import semmle.go.dataflow.TaintTracking
import CsvFlow::PathGraph

class CsvWriteSink extends DataFlow::Node {
  CsvWriteSink() {
    exists(DataFlow::MethodCallNode m |
      // encoding/csv: csv.Writer.Write([]string) / WriteAll
      m.getTarget().hasQualifiedName("encoding/csv", "Writer", ["Write", "WriteAll"]) and
      this = m.getArgument(0)
    )
    or
    exists(DataFlow::MethodCallNode m |
      // excelize: f.SetCellValue(sheet, axis, value) — value is arg 2
      m.getTarget().getName() = "SetCellValue" and
      this = m.getArgument(2)
    )
  }
}

module CsvCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof UntrustedFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof CsvWriteSink }
}

module CsvFlow = TaintTracking::Global<CsvCfg>;

from CsvFlow::PathNode source, CsvFlow::PathNode sink
where CsvFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value from $@ written to a CSV/XLSX cell without leading-" +
  "character escaping.",
  source.getNode(), "remote source"
