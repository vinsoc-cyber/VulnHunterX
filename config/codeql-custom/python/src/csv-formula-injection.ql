/**
 * @name Tainted value written to CSV/XLSX cell
 * @description User input written to a CSV / XLSX cell via `csv.writer`,
 *              `pandas.to_csv`, `openpyxl`, or `xlsxwriter` without
 *              escaping leading `=`/`+`/`-`/`@` characters is interpreted
 *              as a formula in Excel / LibreOffice.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id py/csv-formula-injection
 * @tags external/cwe/cwe-1236
 *       security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import CsvFormulaFlow::PathGraph

class CsvWriteSink extends DataFlow::Node {
  CsvWriteSink() {
    // csv.writer.writerow / writerows
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() in ["writerow", "writerows"] and
      this = m.getArg(0)
    )
    or
    // pandas DataFrame.to_csv — the data being written is implicit;
    // anchor on the value passed into DataFrame()/Series()
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "to_csv" and
      this = c.getObject()
    )
    or
    // openpyxl ws.cell(row, column, value=...)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() = "cell" and
      this = m.getArgByName("value")
    )
    or
    // xlsxwriter worksheet.write(row, col, value)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() in ["write", "write_string", "write_row"] and
      this = m.getArg(2)
    )
  }
}

module CsvCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n instanceof CsvWriteSink }
}

module CsvFormulaFlow = TaintTracking::Global<CsvCfg>;

from CsvFormulaFlow::PathNode source, CsvFormulaFlow::PathNode sink
where CsvFormulaFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Value from $@ written to CSV/XLSX without leading-character escaping.",
  source.getNode(), "remote source"
