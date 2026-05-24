/**
 * @name Tainted value written to CSV/XLSX cell
 * @description User input written to a CSV-style output without escaping
 *              leading `=`/`+`/`-`/`@` is interpreted as a formula in
 *              Excel / LibreOffice / Google Sheets, enabling DDE /
 *              HYPERLINK / WEBSERVICE payload execution.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id js/csv-formula-injection
 * @tags external/cwe/cwe-1236
 *       security
 */

import javascript
import DataFlow::PathGraph

class CsvWriteSink extends DataFlow::Node {
  CsvWriteSink() {
    // papaparse: Papa.unparse(data)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() = "unparse" and
      m.getReceiver().asExpr().toString() = "Papa" and
      this = m.getArgument(0)
    )
    or
    // csv-stringify
    exists(DataFlow::InvokeNode i |
      i.getCalleeName() in ["stringify", "csvStringify"] and
      this = i.getArgument(0)
    )
    or
    // exceljs: worksheet.addRow(values)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() = "addRow" and
      this = m.getArgument(0)
    )
    or
    // xlsx: XLSX.utils.aoa_to_sheet(data) / json_to_sheet(data)
    exists(DataFlow::MethodCallNode m |
      m.getMethodName() in ["aoa_to_sheet", "json_to_sheet"] and
      this = m.getArgument(0)
    )
  }
}

class CsvConfig extends TaintTracking::Configuration {
  CsvConfig() { this = "js/csv-formula-injection" }

  override predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node n) { n instanceof CsvWriteSink }
}

from CsvConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Value from $@ written to CSV/XLSX without leading-character escaping.",
  source.getNode(), "remote source"
