/**
 * @name Tainted value written to CSV/XLSX cell without escaping
 * @description User input written to a CSV/XLSX cell without escaping
 *              a leading `=`/`+`/`-`/`@` is interpreted as a formula
 *              when a victim opens the file in Excel, LibreOffice, or
 *              Google Sheets. Attackers can use DDE / HYPERLINK / cmd|
 *              payloads to phish credentials or execute commands.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision low
 * @id java/csv-formula-injection
 * @tags external/cwe/cwe-1236
 *       security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import CsvFlow::PathGraph

/** A CSV/XLSX cell-write call. */
class CsvWriteSink extends Expr {
  CsvWriteSink() {
    exists(MethodCall m |
      this = m.getAnArgument() and
      (
        // Apache Commons CSV
        m.getMethod().hasName(["print", "printRecord", "printRecords"]) and
        m.getMethod().getDeclaringType().getQualifiedName()
            .regexpMatch("org\\.apache\\.commons\\.csv\\..*")
        or
        // OpenCSV
        m.getMethod().hasName(["writeNext", "write"]) and
        m.getMethod().getDeclaringType().getQualifiedName()
            .regexpMatch("com\\.opencsv\\..*")
        or
        // Apache POI Cell.setCellValue
        m.getMethod().hasName("setCellValue") and
        m.getMethod().getDeclaringType().getQualifiedName()
            .regexpMatch("org\\.apache\\.poi\\..*")
      )
    )
  }
}

module CsvCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof CsvWriteSink }
}

module CsvFlow = TaintTracking::Global<CsvCfg>;

from CsvFlow::PathNode source, CsvFlow::PathNode sink
where CsvFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Value from $@ written to a CSV/XLSX cell — escape leading " +
  "'=', '+', '-', '@', tab, or CR to prevent formula injection.",
  source.getNode(), "remote source"
