/**
 * @name ZipEntry name flows into File path without normalize check
 * @description Extracting `ZipEntry.getName()` into a `File`, `Path`, or
 *              `FileOutputStream` without first verifying that the
 *              resolved path stays within a base directory allows the
 *              ZipSlip attack (CVE-2018-1002) — entries named
 *              `../../etc/passwd` overwrite arbitrary files. Covers
 *              `java.util.zip`, Apache Commons Compress, and tarball
 *              extraction libraries.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id java/zip-slip
 * @tags external/cwe/cwe-22
 *       security
 */

import java
import semmle.code.java.dataflow.TaintTracking
import ZipSlipFlow::PathGraph

/** A call returning the name of a zip / tar / archive entry. */
class ArchiveEntryNameCall extends MethodCall {
  ArchiveEntryNameCall() {
    this.getMethod().hasName(["getName", "getRealName"]) and
    (
      this.getMethod().getDeclaringType().getASupertype*()
          .hasQualifiedName("java.util.zip", "ZipEntry")
      or
      this.getMethod().getDeclaringType().getQualifiedName()
          .regexpMatch("org\\.apache\\.commons\\.compress\\.archivers\\..*Entry")
      or
      this.getMethod().getDeclaringType().getName().regexpMatch(".*ArchiveEntry")
    )
  }
}

/** A file-write / file-open sink whose path argument is the receiver. */
class FilePathSink extends Expr {
  FilePathSink() {
    // new File(String)
    exists(ConstructorCall c |
      c.getConstructedType().hasQualifiedName("java.io", ["File", "FileOutputStream",
                                                          "FileWriter", "RandomAccessFile"]) and
      this = c.getAnArgument()
    )
    or
    // Paths.get(String)
    exists(MethodCall m |
      m.getMethod().hasName("get") and
      m.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
      this = m.getAnArgument()
    )
    or
    // Files.newOutputStream(Path, ...)
    exists(MethodCall m |
      m.getMethod().hasName(["newOutputStream", "newBufferedWriter", "copy"]) and
      m.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      this = m.getArgument(0)
    )
  }
}

module ZipSlipCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(ArchiveEntryNameCall c | n.asExpr() = c)
  }

  predicate isSink(DataFlow::Node n) { n.asExpr() instanceof FilePathSink }

  /** Treat `Path.normalize().startsWith(base)` as a sanitiser. */
  predicate isBarrier(DataFlow::Node n) {
    exists(MethodCall m |
      m.getMethod().hasName("startsWith") and
      m.getQualifier().(MethodCall).getMethod().hasName("normalize") and
      n.asExpr() = m.getAnArgument()
    )
  }
}

module ZipSlipFlow = TaintTracking::Global<ZipSlipCfg>;

from ZipSlipFlow::PathNode source, ZipSlipFlow::PathNode sink
where ZipSlipFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Archive entry name from $@ flows into a file path without a " +
  "normalize().startsWith(baseDir) check — ZipSlip.",
  source.getNode(), "archive entry"
